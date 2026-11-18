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
    row = session.get(models.DiscoveryRun, run_id)
    return bool(row and row.cancel_requested_at is not None)


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
