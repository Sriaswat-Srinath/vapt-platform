"""Worker tasks.

The worker is the component that can reach vapt_lab, so it is the AUTHORITATIVE
evaluator of gate 8 (resolve-once-and-pin). Before any request is sent it
re-evaluates the FULL gate chain locally and persists its own ScopeDecision; a
denial blocks the run. The API's earlier decision is provisional with respect to
resolution and is recorded as such.
"""
from __future__ import annotations
import datetime as dt
import json
import os
import pathlib
import time
from typing import Any
import structlog
from sqlalchemy import select
from .. import audit, models, services
from ..config import settings
from ..db import session_factory
from ..discovery import inventory
from ..safety import scope_policy as sp
from .celery_app import celery
from .http_client import Budget, Cancelled, GuardedClient, BudgetExhausted

log = structlog.get_logger()
FIXTURE_ROOT = pathlib.Path("/srv/fixtures")
CANCEL_CHECK_INTERVAL_SECONDS = 2


def _event(session, run: models.DiscoveryRun, to_state: str, message: str) -> None:
    log.info("discovery_state", run_id=str(run.id), state=to_state, message=message)


def _cancelled(session, run_id: Any) -> bool:
    """Read the flag from the DATABASE, not the identity map.

    `session.get()` returns the cached instance, so a cancel committed by the
    API process would never be observed. Ending the transaction first means a
    READ COMMITTED snapshot actually sees it, and selecting the column (not the
    entity) bypasses the identity map.
    """
    session.commit()
    return session.execute(
        select(models.DiscoveryRun.cancel_requested_at).where(
            models.DiscoveryRun.id == run_id)).scalar() is not None


@celery.task(name="vapt.run_discovery", bind=True)
def run_discovery(self, run_id: str) -> dict[str, Any]:  # noqa: ANN001
    session = session_factory()()
    try:
        run = session.get(models.DiscoveryRun, run_id)
        if run is None:
            return {"error": "run not found"}
        asset = session.get(models.Asset, run.asset_id)
        run.state, run.started_at = "running", dt.datetime.now(dt.timezone.utc)
        session.commit()

        # ---- authoritative preflight, with real resolution from the worker ----
        if run.source == "live":
            req = services.build_scope_request(
                session, asset=asset, profile_key=run.profile_key,
                path=asset.base_path or "/", method="GET", subject_type="discovery_run")
            # (a discovery run is not a scan_job, so it never counts itself)
            result = sp.evaluate(req)
            decision = services.persist_decision(
                session, result, subject_type="discovery_run", subject_id=str(run.id),
                asset_id=asset.id, actor_kind="system", actor_id="worker")
            run.scope_decision_id = decision.id
            audit.record(session, action="worker_preflight", actor_kind="system",
                         actor_id="worker", outcome=result.decision,
                         subject_type="discovery_run", subject_id=str(run.id),
                         detail={"first_failure": (result.first_failure.gate
                                                   if result.first_failure else None)})
            if not result.allowed:
                run.state = "blocked"
                run.stop_reason = "scope_denied"
                run.error = (f"gate {result.first_failure.gate}: {result.first_failure.reason}"
                             if result.first_failure else "denied")
                run.finished_at = dt.datetime.now(dt.timezone.utc)
                session.commit()
                return {"state": "blocked", "reason": run.error}
            run.pinned_ips = list(result.resolved_ips)
            session.commit()

        pages = 0
        try:
            if run.source == "fixture":
                pages = _run_fixture(session, asset, run)
            else:
                pages = _run_live(session, asset, run)
            run.coverage_complete = True
            run.stop_reason = "ok"
            run.state = "completed"
        except Cancelled:
            run.state, run.stop_reason, run.coverage_complete = "cancelled", "cancelled", False
        except BudgetExhausted as exc:
            run.state, run.stop_reason, run.coverage_complete = "completed", "budget_exhausted", False
            run.error = str(exc)
        except Exception as exc:                            # noqa: BLE001
            run.state, run.stop_reason, run.error = "failed", "error", f"{type(exc).__name__}: {exc}"
            log.error("discovery_failed", run_id=str(run.id), error=str(exc))
        run.pages_seen = pages
        run.finished_at = dt.datetime.now(dt.timezone.utc)
        written = inventory.build_candidates(session, asset=asset, run=run)
        audit.record(session, action="discovery_finished", actor_kind="system", actor_id="worker",
                     outcome="ok" if run.state == "completed" else "error",
                     subject_type="discovery_run", subject_id=str(run.id),
                     detail={"state": run.state, "pages_seen": pages,
                             "stop_reason": run.stop_reason,
                             "redirects_blocked": run.redirects_blocked,
                             "candidate_tests": written})
        session.commit()
        return {"state": run.state, "pages_seen": pages, "candidate_tests": written}
    finally:
        session.close()


def _run_fixture(session, asset: models.Asset, run: models.DiscoveryRun) -> int:
    """Replay hand-authored synthetic fixtures. NO network access at all."""
    folder = FIXTURE_ROOT / asset.asset_identifier.lower()
    if not folder.is_dir():
        raise FileNotFoundError(f"no fixtures for {asset.asset_identifier} at {folder}")
    pages = 0
    for f in sorted(folder.glob("*.json")):
        if _cancelled(session, run.id):
            raise Cancelled("cancellation requested")
        doc = json.loads(f.read_text())
        inventory.record_response(session, asset=asset, run=run, path=doc["path"],
                                  status=int(doc["status"]),
                                  headers={k.lower(): v for k, v in doc["headers"].items()},
                                  body=doc.get("body", ""))
        pages += 1
        run.requests_made = 0          # fixtures make no requests
        session.commit()
    return pages


def _run_live(session, asset: models.Asset, run: models.DiscoveryRun) -> int:
    """Crawl the authorised target through the guarded client."""
    profile = session.execute(select(models.ScanProfile).where(
        models.ScanProfile.key == run.profile_key)).scalar_one()
    rules = session.execute(select(models.ScopeRule).where(
        models.ScopeRule.asset_id == asset.id)).scalars().all()
    allowed = tuple(r.path_prefix for r in rules if r.kind == "include") or ("/",)
    excluded = tuple(r.path_prefix for r in rules if r.kind == "exclude")
    budget = Budget(max_requests_per_second=profile.max_requests_per_second,
                    max_total_requests=profile.max_total_requests,
                    max_duration_seconds=profile.max_duration_seconds)
    run.budget_snapshot = {"max_requests_per_second": profile.max_requests_per_second,
                           "max_total_requests": profile.max_total_requests,
                           "max_duration_seconds": profile.max_duration_seconds,
                           "spider_max_children": profile.spider_max_children}
    pinned = (run.pinned_ips or [None])[0]
    if not pinned:
        raise RuntimeError("no pinned IP: refusing to send any request")
    queue: list[str] = [asset.base_path or "/"]
    seen: set[str] = set()
    pages = 0
    with GuardedClient(pinned_ip=pinned, host=asset.hostname, port=asset.port,
                       scheme=asset.protocol, budget=budget,
                       is_cancelled=lambda: _cancelled(session, run.id),
                       allowed_path_prefixes=allowed,
                       excluded_path_prefixes=excluded) as client:
        while queue and pages < profile.spider_max_children:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            resp = client.get(path)
            run.requests_made = budget.requests_made
            run.redirects_blocked = client.redirects_blocked
            if resp is None:
                continue
            inventory.record_response(session, asset=asset, run=run, path=path,
                                      status=resp.status_code, headers=resp.headers,
                                      body=resp.text)
            pages += 1
            session.commit()
            if "html" in (resp.headers.get("content-type") or ""):
                from ..discovery import extractors
                base = f"{asset.protocol}://{asset.hostname}:{asset.port}"
                for href in extractors.parse_html(resp.text).links:
                    nurl = extractors.normalize_url(base, href)
                    if nurl and nurl.startswith(base):
                        np = nurl[len(base):] or "/"
                        if np not in seen and client.path_in_scope(np.split("?")[0]):
                            queue.append(np.split("?")[0])
    return pages


# =============================================================== assessments ==
def _job_cancelled(session, job_id: Any) -> bool:
    """Read the flag from the DATABASE, not the identity map — see _cancelled."""
    session.commit()
    return session.execute(
        select(models.ScanJob.cancel_requested_at).where(
            models.ScanJob.id == job_id)).scalar() is not None


def _job_event(session, job: models.ScanJob, to_state: str, phase: str | None,
               message: str) -> None:
    session.add(models.ScanJobEvent(job_id=job.id, from_state=job.state, to_state=to_state,
                                    phase=phase, message=message))
    job.state = to_state
    if phase:
        job.phase = phase
    session.flush()


def _ingest(session, *, job: models.ScanJob, asset: models.Asset, adapter_name: str,
            adapter_version: str | None, batch) -> tuple[int, int]:
    """Store verbatim observations. An observation about anything other than the
    registered asset is REJECTED and recorded as a rejection, never stored
    (ADR-0011 R3 §13 / invariant I1)."""
    from urllib.parse import urlsplit
    stored = rejected = 0
    expected_host = asset.hostname.lower()
    for obs in batch.items:
        url = obs.observed_url or ""
        host = (urlsplit(url).hostname or "").lower()
        port = urlsplit(url).port or asset.port
        if url and (host != expected_host or port != asset.port):
            session.add(models.IngestionRejection(
                job_id=job.id, asset_id=asset.id, reason="host_mismatch",
                observed_url=url[:1024], payload_sha256=obs.payload_sha256,
                trace_id=job.trace_id))
            rejected += 1
            continue
        from ..evidence import store as blob_store
        req_blob = (blob_store.put(session, obs.request_text.encode("utf-8", "replace"),
                                   media_type="message/http")
                    if obs.request_text else None)
        resp_blob = (blob_store.put(session, obs.response_text.encode("utf-8", "replace"),
                                    media_type="message/http")
                     if obs.response_text else None)
        session.add(models.RawObservation(
            job_id=job.id, asset_id=asset.id, adapter_name=adapter_name,
            adapter_version=adapter_version, adapter_rule_id=obs.adapter_rule_id,
            payload=obs.payload, payload_sha256=obs.payload_sha256,
            request_sha256=obs.request_sha256, response_sha256=obs.response_sha256,
            observed_url=url[:1024] or None,
            observed_peer_ip=(job.pinned_ips or [None])[0],
            request_blob_id=req_blob.id if req_blob else None,
            response_blob_id=resp_blob.id if resp_blob else None))
        stored += 1
    session.flush()
    return stored, rejected


@celery.task(name="vapt.run_assessment", bind=True)
def run_assessment(self, job_id: str) -> dict[str, Any]:  # noqa: ANN001
    """Full assessment lifecycle. The worker is the authoritative gate evaluator
    and holds the global daemon lease across the entire session (ADR-0008 R2)."""
    from ..scanners import base as sb
    from ..scanners.registry import get_adapter
    from .daemon_lease import DaemonDirty, ExclusiveDaemonLease, LeaseUnavailable, mark_dirty

    session = session_factory()()
    lease: ExclusiveDaemonLease | None = None
    try:
        job = session.get(models.ScanJob, job_id)
        if job is None:
            return {"error": "job not found"}
        asset = session.get(models.Asset, job.asset_id)
        profile = session.execute(select(models.ScanProfile).where(
            models.ScanProfile.key == job.profile_key)).scalar_one()
        _job_event(session, job, "preflight", "preflight", "worker claimed the job")
        session.commit()

        # ---- 1. authoritative preflight, with real resolution ---------------
        # Re-evaluate in the SAME mode the request was admitted under. A
        # fixture job cannot become a live one, and vice versa.
        req = services.build_scope_request(session, asset=asset, profile_key=job.profile_key,
                                           path=asset.base_path or "/", method="GET",
                                           subject_type="scan_job",
                                           mode=job.mode or sp.MODE_LIVE,
                                           exclude_job_id=job.id)
        result = sp.evaluate(req)
        decision = services.persist_decision(session, result, subject_type="scan_job",
                                             subject_id=str(job.id), asset_id=asset.id,
                                             actor_kind="system", actor_id="worker")
        job.scope_decision_id = decision.id
        audit.record(session, action="worker_preflight", actor_kind="system", actor_id="worker",
                     outcome=result.decision, subject_type="scan_job", subject_id=str(job.id),
                     detail={"first_failure": (result.first_failure.gate
                                               if result.first_failure else None)})
        if not result.allowed:
            _job_event(session, job, "blocked", "preflight",
                       f"gate {result.first_failure.gate}: {result.first_failure.reason}")
            job.stop_reason, job.finished_at = "scope_denied", dt.datetime.now(dt.timezone.utc)
            session.commit()
            return {"state": "blocked", "gate": result.first_failure.gate}
        job.pinned_ips = list(result.resolved_ips)

        adapter_name = job.adapter_name or settings().default_scanner_adapter
        if job.mode == sp.MODE_FIXTURE and adapter_name != "mock":
            _job_event(session, job, "blocked", "preflight",
                       "fixture mode requires the mock adapter")
            job.stop_reason, job.finished_at = "scope_denied", dt.datetime.now(dt.timezone.utc)
            session.commit()
            return {"state": "blocked", "reason": "fixture mode requires the mock adapter"}
        adapter = get_adapter(adapter_name)
        caps = adapter.capabilities()
        job.requires_exclusive_daemon = caps.requires_exclusive_daemon
        session.commit()

        spec = sb.ScanJobSpec(
            job_id=str(job.id), mode=job.mode or sp.MODE_LIVE,
            asset=sb.AssetSnapshot(asset_id=str(asset.id), asset_identifier=asset.asset_identifier,
                                   hostname=asset.hostname, protocol=asset.protocol,
                                   port=asset.port, base_path=asset.base_path or "/"),
            profile=sb.ProfileSnapshot(
                key=profile.key, adapter_name=profile.adapter_name,
                is_intrusive=profile.is_intrusive, active_scan=profile.active_scan,
                max_requests_per_second=profile.max_requests_per_second,
                max_total_requests=profile.max_total_requests,
                max_duration_seconds=profile.max_duration_seconds,
                spider_max_depth=profile.spider_max_depth,
                spider_max_children=profile.spider_max_children,
                excluded_path_patterns=tuple(profile.excluded_path_patterns or ()),
                method_denylist=tuple(profile.method_denylist or ()),
                excluded_rule_ids=tuple(profile.excluded_rule_ids or ())),
            pinned_ips=tuple(job.pinned_ips or ()),
            seed_paths=(asset.base_path or "/",),
            included_path_prefixes=tuple(
                r.path_prefix for r in session.execute(select(models.ScopeRule).where(
                    models.ScopeRule.asset_id == asset.id,
                    models.ScopeRule.kind == "include")).scalars().all()) or ("/",),
            excluded_path_prefixes=tuple(
                r.path_prefix for r in session.execute(select(models.ScopeRule).where(
                    models.ScopeRule.asset_id == asset.id,
                    models.ScopeRule.kind == "exclude")).scalars().all()),
            scope_decision_allowed=True, scope_decision_id=str(decision.id))

        # ---- 2. the global lease wraps the ENTIRE session lifecycle ---------
        if caps.requires_exclusive_daemon:
            try:
                lease = ExclusiveDaemonLease(caps.name, job.id).__enter__()
                job.daemon_lease_id = lease.lease_id
            except (LeaseUnavailable, DaemonDirty) as exc:
                _job_event(session, job, "blocked", "preflight", str(exc))
                job.stop_reason = "daemon_unavailable"
                job.finished_at = dt.datetime.now(dt.timezone.utc)
                session.commit()
                return {"state": "blocked", "reason": str(exc)}

        handle = None
        dirty_reason: str | None = None
        try:
            # ---- 3. session isolation: newSession + assert stores empty -----
            if hasattr(adapter, "begin_session"):
                detail = adapter.begin_session(spec)
                job.session_asserted_empty_at = dt.datetime.now(dt.timezone.utc)
                _job_event(session, job, "running", "preflight", f"session asserted empty: {detail}")
            else:
                _job_event(session, job, "running", "preflight", "adapter needs no shared session")
            session.commit()

            handle = adapter.start(spec)
            job.adapter_handle = dict(handle.external_ids)
            _job_event(session, job, "running", "spider", "scan started")
            session.commit()

            # ---- 4. poll with bounded cancellation -------------------------
            sla = int(os.environ.get("CANCELLATION_SLA_SECONDS", "120"))
            started = time.monotonic()
            cancelled = False
            while True:
                if _job_cancelled(session, job.id):
                    cancelled = True
                    break
                progress = adapter.poll(handle)
                job.requests_made = progress.requests_made
                job.phase = progress.phase
                if lease:
                    lease.heartbeat()
                session.commit()
                if not progress.is_running:
                    break
                if time.monotonic() - started > profile.max_duration_seconds:
                    job.stop_reason = "budget_exhausted"
                    break
                time.sleep(CANCEL_CHECK_INTERVAL_SECONDS)

            if cancelled:
                cancel_started = time.monotonic()
                res = adapter.cancel(handle)
                elapsed = time.monotonic() - cancel_started
                if not res.confirmed_stopped or elapsed > sla:
                    dirty_reason = (f"cancellation unconfirmed after {elapsed:.1f}s: {res.detail}")
                    _job_event(session, job, "failed", "collect", dirty_reason)
                    job.stop_reason = "cancel_unconfirmed"
                else:
                    _job_event(session, job, "cancelled", "collect",
                               f"cancelled in {elapsed:.1f}s ({res.detail})")
                    job.stop_reason = "cancelled"
                job.coverage_complete = False
            else:
                # ---- 5. collect verbatim observations -----------------------
                _job_event(session, job, "running", "collect", "collecting observations")
                session.commit()
                cursor, stored, rejected = None, 0, 0
                while True:
                    batch = adapter.collect(handle, cursor)
                    s_, r_ = _ingest(session, job=job, asset=asset, adapter_name=caps.name,
                                     adapter_version=caps.version, batch=batch)
                    stored, rejected = stored + s_, rejected + r_
                    session.commit()
                    if not batch.cursor:
                        break
                    cursor = batch.cursor
                job.observations_count = stored
                job.coverage_complete = job.stop_reason != "budget_exhausted"
                session.commit()
                # ---- normalise -> dedup -> evidence -> validate -> CVSS -----
                _job_event(session, job, "running", "normalize", "building findings")
                session.commit()
                from ..findings_pipeline import process_job
                fstats = process_job(session, job, asset)
                _job_event(session, job, "completed", "done",
                           f"stored {stored} observations, rejected {rejected} out-of-scope; "
                           f"{fstats['findings_new']} new findings, "
                           f"{fstats.get('confirmed', 0)} confirmed, "
                           f"{fstats.get('false_positive', 0)} false positive, "
                           f"{fstats.get('inconclusive', 0)} inconclusive, "
                           f"{fstats.get('not_applicable', 0)} not applicable")
                job.stop_reason = job.stop_reason or "ok"
        except sb.ScopeRefused as exc:
            _job_event(session, job, "blocked", "preflight", f"adapter refused: {exc}")
            job.stop_reason = "scope_denied"
        except Exception as exc:                                   # noqa: BLE001
            dirty_reason = dirty_reason or f"{type(exc).__name__}: {exc}"
            _job_event(session, job, "failed", job.phase, dirty_reason)
            job.stop_reason = job.stop_reason or "error"
            job.error = dirty_reason
            log.error("assessment_failed", job_id=str(job.id), error=str(exc))
        finally:
            # ---- 6. teardown, always; failure marks the daemon dirty --------
            if handle is not None:
                try:
                    td = adapter.teardown(handle)
                    if td.confirmed_stopped:
                        job.teardown_confirmed_at = dt.datetime.now(dt.timezone.utc)
                        session.add(models.ScanJobEvent(
                            job_id=job.id, from_state=job.state, to_state=job.state,
                            phase="done", message=f"teardown confirmed: {td.detail}"))
                    else:
                        dirty_reason = f"teardown unconfirmed: {td.detail}"
                        job.stop_reason = "teardown_unconfirmed"
                        job.state = "failed"
                        session.add(models.ScanJobEvent(
                            job_id=job.id, from_state=job.state, to_state="failed",
                            phase="done", message=dirty_reason))
                except Exception as exc:                           # noqa: BLE001
                    dirty_reason = f"teardown raised {type(exc).__name__}: {exc}"
                    job.stop_reason = "teardown_unconfirmed"
                    job.state = "failed"
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            audit.record(session, action="assessment_finished", actor_kind="system",
                         actor_id="worker", outcome="ok" if job.state == "completed" else "error",
                         subject_type="scan_job", subject_id=str(job.id),
                         detail={"state": job.state, "stop_reason": job.stop_reason,
                                 "observations": job.observations_count,
                                 "coverage_complete": job.coverage_complete})
            session.commit()
            if lease is not None:
                lease.release(dirty=bool(dirty_reason), reason=dirty_reason)
                lease.__exit__(None, None, None)
        return {"state": job.state, "stop_reason": job.stop_reason,
                "observations": job.observations_count}
    finally:
        session.close()


@celery.task(name="vapt.scanner_reset", bind=True)
def scanner_reset(self, reset_id: str, adapter: str) -> dict[str, Any]:  # noqa: ANN001
    """Verification-gated daemon reset, performed by the WORKER.

    The api has no route to vapt_lab by design, so it cannot verify the daemon;
    it records the request and delegates here. The dirty flag clears only when
    every step passes (ADR-0008 R3 §10). The platform cannot restart containers:
    an unreachable daemon sets requires_operator_restart.
    """
    from .daemon_lease import daemon_state
    from ..scanners.zap.client import ZapApiError, ZapClient

    session = session_factory()()
    steps: list[dict[str, Any]] = []
    failing: str | None = None
    client = None
    try:
        row = session.get(models.ScannerReset, reset_id)
        st = daemon_state(session, adapter)
        held = session.execute(select(models.ScannerDaemonLease).where(
            models.ScannerDaemonLease.adapter_name == adapter,
            models.ScannerDaemonLease.lease_state == "held")).scalars().all()
        if held:
            steps.append({"step": "R1", "pass": False, "detail": "a job holds the exclusive lease"})
            failing = "R1"
        if failing is None:
            client = ZapClient()
            try:
                version = client.version()
                steps.append({"step": "R2", "pass": bool(version), "detail": f"version={version}"})
                failing = None if version else "R2"
            except ZapApiError as exc:
                steps.append({"step": "R2", "pass": False, "detail": f"unreachable: {exc}"})
                failing = "R2"
        if failing is None:
            try:
                client.new_session(f"reset-{int(time.time())}")
                steps.append({"step": "R4", "pass": True, "detail": "newSession"})
                empty, detail = client.stores_empty()
                steps.append({"step": "R5", "pass": empty, "detail": detail})
                failing = None if empty else "R5"
            except ZapApiError as exc:
                steps.append({"step": "R4", "pass": False, "detail": str(exc)})
                failing = "R4"
        if failing is None:
            try:
                probe = f"vapt-probe-{int(time.time())}"
                client.new_context(probe)
                present = probe in client.contexts()
                client.remove_context(probe)
                steps.append({"step": "R6", "pass": present, "detail": "context create/read/remove"})
                failing = None if present else "R6"
            except ZapApiError as exc:
                steps.append({"step": "R6", "pass": False, "detail": str(exc)})
                failing = "R6"
        if failing is None:
            try:
                marker = f"vapt-instance-{int(time.time())}"
                client.new_context(marker)
                st.instance_marker, st.observed_version = marker, client.version()
                steps.append({"step": "R7", "pass": True, "detail": f"marker={marker}"})
            except ZapApiError as exc:
                steps.append({"step": "R7", "pass": False, "detail": str(exc)})
                failing = "R7"
        cleared = failing is None
        if cleared:
            st.is_dirty, st.dirty_reason, st.requires_operator_restart = False, None, False
            st.last_reset_at = dt.datetime.now(dt.timezone.utc)
        elif failing in ("R2", "R4"):
            st.requires_operator_restart = True
        st.last_reset_outcome = {"steps": steps, "cleared": cleared, "failing_step": failing}
        if row is not None:
            row.steps = {"steps": steps}
            row.cleared_dirty = cleared
            row.failing_step = failing
        audit.record(session, action="scanner_reset_performed", actor_kind="system",
                     actor_id="worker", outcome="ok" if cleared else "error",
                     subject_type="scanner_daemon", subject_id=adapter,
                     detail={"cleared": cleared, "failing_step": failing, "steps": steps,
                             "reset_id": reset_id})
        session.commit()
        return {"cleared_dirty": cleared, "failing_step": failing, "steps": steps}
    finally:
        if client is not None:
            client.close()
        session.close()
