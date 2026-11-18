"""System endpoints: health, readiness, capabilities, isolation ingest."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from ... import audit, errors, models, retention, schemas, services
from ...config import settings
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


@router.get("/system/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/system/readiness")
def readiness(session: Session = Depends(get_session)) -> dict[str, object]:
    checks: dict[str, object] = {}
    try:
        session.execute(text("select 1"))
        checks["database"] = "ok"
    except Exception as exc:                                  # noqa: BLE001
        checks["database"] = f"error: {exc.__class__.__name__}"
    try:
        import redis
        s = settings()
        client = redis.Redis.from_url(s.redis_url, password=s.redis_password,
                                      socket_connect_timeout=2)
        client.ping()
        checks["redis"] = "ok"
    except Exception as exc:                                  # noqa: BLE001
        checks["redis"] = f"error: {exc.__class__.__name__}"
    iso = services.latest_isolation(session)
    checks["lab_isolation"] = ({"isolation_passed": iso.isolation_passed,
                                "valid_until": iso.valid_until.isoformat(),
                                "stale": iso.valid_until <= dt.datetime.now(dt.timezone.utc)}
                               if iso else "never reported")
    checks["ready"] = checks["database"] == "ok"
    return checks


@router.get("/system/capabilities")
def capabilities(session: Session = Depends(get_session)) -> dict[str, object]:
    s = settings()
    attested = services.attested_identity_count(session)
    effective = services.effective_dual_control(session)
    return {
        "scanner_execution_enabled": s.scanner_execution_enabled,
        "zap_adapter_enabled": s.zap_adapter_enabled,
        "active_scan_enabled": s.active_scan_enabled,
        "default_scanner_adapter": s.default_scanner_adapter,
        "dual_control": {
            "flag": s.dual_control_available,
            "attested_distinct_active_identities": attested,
            "required": s.dual_control_min_identities,
            "effective": effective,
            "note": ("Dual control unavailable — single operator environment; intrusive profiles "
                     "disabled. Approvals recorded here are not independent human approval."
                     if not effective else "Dual control available."),
        },
        "llm_enabled": s.llm_enabled,
        "evidence_encryption": "none (host FDE assumed, unverified)",
        "environment_policy": "mock_lab only",
        "policy_version": __import__("app.safety.scope_policy", fromlist=["x"]).POLICY_VERSION,
    }


@router.get("/system/isolation")
def isolation(session: Session = Depends(get_session)) -> dict[str, object]:
    iso = services.latest_isolation(session)
    if iso is None:
        return {"reported": False,
                "detail": "no lab isolation check reported; run `make lab-check` and report it"}
    return {"reported": True, "checked_at": iso.checked_at, "valid_until": iso.valid_until,
            "isolation_passed": iso.isolation_passed, "egress_blocked": iso.egress_blocked,
            "dns_contained": iso.dns_contained, "host_hygiene_passed": iso.host_hygiene_passed,
            "host_wildcard_listeners": iso.host_wildcard_listeners,
            "stale": iso.valid_until <= dt.datetime.now(dt.timezone.utc)}


@router.post("/system/isolation/report", status_code=201)
def report_isolation(payload: schemas.IsolationReport,
                     session: Session = Depends(get_session),
                     p: Principal = Depends(require_role("admin")),
                     trace: str = Depends(trace_id)) -> dict[str, object]:
    """Ingest the output of scripts/lab_isolation_check.sh. Admin only.

    The platform does not read the host filesystem; the operator reports the
    measured result, and gate 2 consumes the latest row.
    """
    row = models.LabIsolationCheck(
        checked_at=payload.checked_at, valid_until=payload.valid_until,
        network_name=payload.network_name, subnet=payload.subnet,
        egress_blocked=payload.egress_blocked, dns_contained=payload.dns_contained,
        isolation_passed=payload.isolation_passed,
        host_hygiene_passed=payload.host_hygiene_passed,
        host_wildcard_listeners=payload.host_wildcard_listeners,
        probe_results={"probes": payload.probe_results or []}, reported_by=p.analyst.id)
    session.add(row)
    audit.record(session, action="lab_isolation_reported", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="lab_isolation_check", trace_id=trace,
                 detail={"isolation_passed": payload.isolation_passed,
                         "host_hygiene_passed": payload.host_hygiene_passed})
    session.commit()
    return {"id": str(row.id), "isolation_passed": row.isolation_passed,
            "valid_until": row.valid_until}


@router.get("/system/retention/policy")
def retention_policy(p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    """What would be purged, and what never is."""
    return retention.policy()


@router.post("/system/retention/purge", status_code=201)
def retention_purge(dry_run: bool = Query(default=True),
                    limit: int | None = Query(default=None, le=5000),
                    older_than_days: int | None = Query(default=None, ge=0, le=3650),
                    session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("admin")),
                    trace: str = Depends(trace_id)):
    """Run one purge pass. ADMIN only, and DRY RUN unless asked otherwise.

    Deleting evidence is irreversible, so the destructive form is opt-in on
    every call rather than a stored setting. A run that halts is still
    recorded — that row is the point of the invariant.
    """
    s = settings()
    if not dry_run and not s.retention_enabled:
        raise errors.conflict(
            "retention-disabled", "Retention purge is disabled",
            "RETENTION_ENABLED is false. A dry run is permitted; deleting is not.")
    started = dt.datetime.now(dt.timezone.utc)
    # `older_than_days` overrides the configured window for THIS run only and is
    # recorded on the row. 0 means "everything unreferenced", which is a real
    # operational need and is why the destructive form needs admin, the
    # retention flag AND an explicit dry_run=false.
    outcome = retention.run(session, dry_run=dry_run, limit=limit, days=older_than_days)
    row = retention.record(session, outcome, triggered_by=p.id, started_at=started)
    audit.record(session, action="retention_purge", actor_kind="human", actor_id=p.id,
                 outcome=outcome.state, subject_type="purge_run", subject_id=str(row.id),
                 trace_id=trace, detail=outcome.as_dict())
    session.commit()
    return {"id": str(row.id), **outcome.as_dict(),
            "note": ("dry run: nothing was deleted" if outcome.dry_run else
                     "blobs were deleted; evidence rows remain, marked purged")}


@router.get("/system/retention/runs")
def retention_runs(limit: int = Query(default=20, le=100),
                   session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    rows = session.execute(select(models.PurgeRun).order_by(
        models.PurgeRun.started_at.desc()).limit(limit)).scalars().all()
    return [{"id": str(r.id), "state": r.state, "dry_run": r.dry_run,
             "retention_version": r.retention_version,
             "evidence_blob_days": r.evidence_blob_days, "scanned": r.scanned,
             "eligible": r.eligible, "purged": r.purged,
             "skipped_referenced": r.skipped_referenced,
             "bytes_reclaimed": r.bytes_reclaimed, "halt_reason": r.halt_reason,
             "halt_detail": r.halt_detail, "triggered_by": r.triggered_by,
             "started_at": r.started_at, "finished_at": r.finished_at} for r in rows]


@router.get("/system/scanner/state")
def scanner_state(session: Session = Depends(get_session),
                  p: Principal = Depends(require_role("analyst", "approver"))):
    """Daemon state per adapter, plus any live lease. Gate 13 consumes this."""
    from ...scanners.registry import registered_adapters
    states = session.execute(select(models.ScannerDaemonState)).scalars().all()
    leases = session.execute(select(models.ScannerDaemonLease).where(
        models.ScannerDaemonLease.lease_state == "held")).scalars().all()
    return {
        "adapters": registered_adapters(),
        "default_adapter": settings().default_scanner_adapter,
        "daemon_state": [{"adapter": s.adapter_name, "is_dirty": s.is_dirty,
                          "dirty_reason": s.dirty_reason, "dirty_since": s.dirty_since,
                          "requires_operator_restart": s.requires_operator_restart,
                          "last_reset_at": s.last_reset_at} for s in states],
        "held_leases": [{"adapter": lease.adapter_name,
                         "job_id": str(lease.job_id) if lease.job_id else None,
                         "holder": lease.holder_worker_id, "acquired_at": lease.acquired_at,
                         "heartbeat_at": lease.heartbeat_at} for lease in leases],
    }


@router.post("/system/scanner/reset")
def scanner_reset(adapter: str = "zap", session: Session = Depends(get_session),
                  p: Principal = Depends(require_role("admin")),
                  trace: str = Depends(trace_id)):
    """Verification-gated reset (ADR-0008 R3 §10).

    The dirty flag clears ONLY when every verification step passes. There is no
    force parameter, no configuration override and no automatic expiry. The
    platform cannot restart containers (no Docker socket): where the daemon is
    unreachable this returns 503 and names the operator action.
    """
    steps: list[dict[str, object]] = []
    st = session.get(models.ScannerDaemonState, adapter)
    if st is None:
        st = models.ScannerDaemonState(adapter_name=adapter, is_dirty=False)
        session.add(st)
        session.flush()
    held = session.execute(select(models.ScannerDaemonLease).where(
        models.ScannerDaemonLease.adapter_name == adapter,
        models.ScannerDaemonLease.lease_state == "held")).scalars().all()
    if held:
        raise errors.conflict("lease-held", "A job holds the scanner lease",
                              "reset is refused while a job holds the exclusive daemon lease")

    if adapter == "mock":
        # The mock adapter has no daemon, so there is nothing to verify remotely.
        steps.append({"step": "R2", "pass": True, "detail": "mock adapter needs no daemon"})
        st.is_dirty, st.dirty_reason, st.requires_operator_restart = False, None, False
        st.last_reset_at = dt.datetime.now(dt.timezone.utc)
        st.last_reset_by = p.analyst.id
        st.last_reset_outcome = {"steps": steps, "cleared": True, "failing_step": None}
        session.add(models.ScannerReset(requested_by=p.analyst.id, adapter_name=adapter,
                                        steps={"steps": steps}, cleared_dirty=True,
                                        failing_step=None, trace_id=trace))
        audit.record(session, action="scanner_reset", actor_kind="human", actor_id=p.id,
                     outcome="ok", subject_type="scanner_daemon", subject_id=adapter,
                     trace_id=trace, detail={"cleared": True, "steps": steps})
        session.commit()
        return {"adapter": adapter, "cleared_dirty": True, "failing_step": None,
                "steps": steps, "is_dirty": st.is_dirty}

    # The api has NO route to vapt_lab by design, so it cannot verify the ZAP
    # daemon itself. It records the request and delegates to the worker, which
    # performs R2-R7 and clears the flag only on a full pass.
    row = models.ScannerReset(requested_by=p.analyst.id, adapter_name=adapter,
                              steps={"steps": [], "delegated": True}, cleared_dirty=False,
                              failing_step=None, trace_id=trace)
    session.add(row)
    session.flush()
    audit.record(session, action="scanner_reset_requested", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scanner_daemon", subject_id=adapter, trace_id=trace,
                 detail={"reset_id": str(row.id), "delegated_to": "worker"})
    session.commit()
    try:
        from ...worker.tasks import scanner_reset as task
        task.apply_async(args=[str(row.id), adapter], queue="vapt")
        enqueued = True
    except Exception:                                      # noqa: BLE001
        enqueued = False
    return {"adapter": adapter, "reset_id": str(row.id), "delegated_to": "worker",
            "enqueued": enqueued, "is_dirty": st.is_dirty,
            "detail": ("the worker performs the verification sequence; poll "
                       "GET /system/scanner/state and GET /system/scanner/resets")}


@router.get("/system/scanner/resets")
def scanner_resets(limit: int = 10, session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("approver"))):
    rows = session.execute(select(models.ScannerReset).order_by(
        models.ScannerReset.at.desc()).limit(min(limit, 50))).scalars().all()
    return [{"id": str(r.id), "at": r.at, "adapter": r.adapter_name,
             "cleared_dirty": r.cleared_dirty, "failing_step": r.failing_step,
             "steps": r.steps} for r in rows]


@router.get("/scan-profiles", response_model=list[schemas.ProfileOut])
def profiles(session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst", "approver"))):
    return session.execute(select(models.ScanProfile).order_by(models.ScanProfile.key)).scalars().all()
