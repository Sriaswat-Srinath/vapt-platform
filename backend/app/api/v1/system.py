"""System endpoints: health, readiness, capabilities, isolation ingest."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from ... import audit, models, schemas, services
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


@router.get("/scan-profiles", response_model=list[schemas.ProfileOut])
def profiles(session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst", "approver"))):
    return session.execute(select(models.ScanProfile).order_by(models.ScanProfile.key)).scalars().all()
