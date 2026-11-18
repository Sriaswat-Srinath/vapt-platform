"""Use-case orchestration: builds immutable snapshots, calls the pure policy,
persists decisions, writes audit rows. The LLM never enters this path.
"""
from __future__ import annotations
import datetime as dt
import socket
from typing import Any
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from . import audit, errors, models
from .config import settings
from .safety import scope_policy as sp

IN_FLIGHT = ("queued", "preflight", "running", "paused", "cancelling")


# ------------------------------------------------------------- resolution ----
def resolve_host(hostname: str) -> tuple[tuple[str, ...], str | None]:
    """Resolve once (ADR-0006). The caller pins the result into the job.

    NOTE on where this runs: the API is attached to internal networks only and
    deliberately has NO route to vapt_lab, so it cannot resolve lab hostnames.
    Authoritative resolve-once-and-pin therefore belongs to the scanner worker
    (which is dual-homed vapt_core + vapt_lab) at execution time. Until the
    worker exists (phase 3), gate 8 denies with that reason rather than
    pretending the target was validated.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        return (), (f"not resolvable from the API ({exc.__class__.__name__}); "
                    "the scanner worker performs resolve-once-and-pin on vapt_lab "
                    "at execution time")
    return tuple(sorted({i[4][0] for i in infos})), None


# ------------------------------------------------------------- dual control ---
def attested_identity_count(session: Session) -> int:
    """Counted live, never trusted from a flag (ADR-0009 R2 §8)."""
    return int(session.execute(
        select(func.count()).select_from(models.OperatorIdentity).where(
            models.OperatorIdentity.is_active.is_(True),
            models.OperatorIdentity.attested_at.isnot(None),
            models.OperatorIdentity.attestation_withdrawn_at.is_(None),
        )
    ).scalar_one())


def effective_dual_control(session: Session) -> bool:
    s = settings()
    return bool(s.dual_control_available and
                attested_identity_count(session) >= s.dual_control_min_identities)


def identity_ok(session: Session, analyst_id: Any) -> bool:
    row = session.execute(select(models.OperatorIdentity).where(
        models.OperatorIdentity.analyst_id == analyst_id)).scalar_one_or_none()
    return bool(row and row.is_active and row.attested_at and not row.attestation_withdrawn_at)


# --------------------------------------------------------------- snapshots ----
def latest_isolation(session: Session) -> models.LabIsolationCheck | None:
    return session.execute(select(models.LabIsolationCheck)
                           .order_by(models.LabIsolationCheck.checked_at.desc())
                           .limit(1)).scalar_one_or_none()


def active_grant(session: Session, asset_id: Any) -> models.ScopeGrant | None:
    rows = session.execute(select(models.ScopeGrant).where(
        models.ScopeGrant.asset_id == asset_id).order_by(
        models.ScopeGrant.created_at.desc())).scalars().all()
    return next((g for g in rows if g.state == "active"), rows[0] if rows else None)


def build_scope_request(session: Session, *, asset: models.Asset | None, profile_key: str | None,
                        path: str = "/", method: str = "GET",
                        subject_type: str = "scan_job",
                        mode: str = sp.MODE_LIVE,
                        exclude_job_id: Any | None = None) -> sp.ScopeRequest:
    s = settings()
    now = dt.datetime.now(dt.timezone.utc)
    iso = latest_isolation(session)
    grant = active_grant(session, asset.id) if asset else None
    profile = session.execute(select(models.ScanProfile).where(
        models.ScanProfile.key == profile_key)).scalar_one_or_none() if profile_key else None
    rules = session.execute(select(models.ScopeRule).where(
        models.ScopeRule.asset_id == asset.id)).scalars().all() if asset else []

    approval_snap = None
    if profile is not None and (profile.is_intrusive or profile.active_scan) and grant is not None:
        appr = session.execute(select(models.Approval).where(
            models.Approval.scope_grant_id == grant.id,
            models.Approval.kind == "intrusive_profile",
            models.Approval.state == "approved").order_by(
            models.Approval.decided_at.desc()).limit(1)).scalar_one_or_none()
        if appr is not None:
            approval_snap = sp.ApprovalSnapshot(
                id=str(appr.id), kind=appr.kind, state=appr.state,
                requested_by=str(appr.requested_by),
                decided_by=str(appr.decided_by) if appr.decided_by else None,
                expires_at=appr.expires_at,
                requester_identity_ok=identity_ok(session, appr.requested_by),
                decider_identity_ok=identity_ok(session, appr.decided_by) if appr.decided_by else False)

    resolved: tuple[str, ...] = ()
    resolution_error: str | None = None
    if asset is not None:
        resolved, resolution_error = resolve_host(asset.hostname)

    # Gate 13 inputs: real daemon state, not a placeholder (ADR-0008 R2 §gate 13).
    adapter_for_profile = profile.adapter_name if profile else None
    daemon_dirty = daemon_lease_held = False
    if adapter_for_profile:
        st = session.get(models.ScannerDaemonState, adapter_for_profile)
        daemon_dirty = bool(st and st.is_dirty)
        daemon_lease_held = bool(session.execute(select(func.count()).select_from(
            models.ScannerDaemonLease).where(
            models.ScannerDaemonLease.adapter_name == adapter_for_profile,
            models.ScannerDaemonLease.lease_state == "held")).scalar_one())

    # Exclude the job being evaluated: a worker re-checking its own job must not
    # count itself as a conflicting in-flight job (gates 11 and 12).
    global_stmt = select(func.count()).select_from(models.ScanJob).where(
        models.ScanJob.state.in_(IN_FLIGHT))
    if exclude_job_id is not None:
        global_stmt = global_stmt.where(models.ScanJob.id != exclude_job_id)
    in_flight_global = int(session.execute(global_stmt).scalar_one())
    in_flight_asset = 0
    if asset is not None:
        asset_stmt = select(func.count()).select_from(models.ScanJob).where(
            models.ScanJob.state.in_(IN_FLIGHT), models.ScanJob.asset_id == asset.id)
        if exclude_job_id is not None:
            asset_stmt = asset_stmt.where(models.ScanJob.id != exclude_job_id)
        in_flight_asset = int(session.execute(asset_stmt).scalar_one())

    return sp.ScopeRequest(
        now=now, subject_type=subject_type, mode=mode, target_url_path=path,
        target_method=method,
        scanner_execution_enabled=s.scanner_execution_enabled,
        active_scan_enabled=s.active_scan_enabled,
        dual_control_available_flag=s.dual_control_available,
        attested_distinct_active_identities=attested_identity_count(session),
        dual_control_min_identities=s.dual_control_min_identities,
        isolation_passed=(iso.isolation_passed if iso else None),
        host_hygiene_passed=(iso.host_hygiene_passed if iso else None),
        host_wildcard_listeners=(iso.host_wildcard_listeners if iso else None),
        isolation_valid_until=(iso.valid_until if iso else None),
        asset_exists=asset is not None,
        asset_state=asset.state if asset else None,
        asset_environment=asset.environment if asset else None,
        asset_hostname=asset.hostname if asset else None,
        asset_port=asset.port if asset else None,
        grant=(sp.GrantSnapshot(
            id=str(grant.id), state=grant.state, document_state=grant.document_state,
            allowed_cidrs=tuple(grant.allowed_cidrs or ()),
            allowed_ports=tuple(grant.allowed_ports or ()),
            allowed_profiles=tuple(grant.allowed_profiles or ()),
            intrusive_allowed=grant.intrusive_allowed, valid_from=grant.valid_from,
            valid_until=grant.valid_until, revoked_at=grant.revoked_at) if grant else None),
        profile=(sp.ProfileSnapshot(
            key=profile.key, adapter_name=profile.adapter_name, is_intrusive=profile.is_intrusive,
            active_scan=profile.active_scan,
            method_denylist=tuple(profile.method_denylist or ()),
            excluded_path_patterns=tuple(profile.excluded_path_patterns or ())) if profile else None),
        approval=approval_snap,
        resolved_ips=resolved, resolution_error=resolution_error,
        scope_rules=tuple(sp.ScopeRuleSnapshot(
            kind=r.kind, host_pattern=r.host_pattern, port=r.port, path_prefix=r.path_prefix,
            method_allowlist=tuple(r.method_allowlist or ())) for r in rules),
        in_flight_jobs_global=in_flight_global, in_flight_jobs_for_asset=in_flight_asset,
        max_concurrent_jobs_global=s.max_concurrent_jobs_global,
        max_concurrent_jobs_per_asset=s.max_concurrent_jobs_per_asset,
        adapter_requires_exclusive_daemon=bool(profile and profile.adapter_name == "zap"),
        daemon_dirty=daemon_dirty, daemon_lease_held=daemon_lease_held,
    )


def persist_decision(session: Session, result: sp.ScopeDecisionResult, *, subject_type: str,
                     subject_id: str | None, asset_id: Any | None, actor_kind: str,
                     actor_id: str | None) -> models.ScopeDecision:
    row = models.ScopeDecision(
        subject_type=subject_type, subject_id=subject_id, asset_id=asset_id,
        policy_version=result.policy_version, decision=result.decision,
        gate_results={"mode": result.mode,
                      "gate_results": [g.as_dict() for g in result.gate_results]},
        resolved_ips=list(result.resolved_ips), actor_kind=actor_kind, actor_id=actor_id)
    session.add(row)
    session.flush()
    return row


def evaluate_and_persist(session: Session, *, asset: models.Asset | None, profile_key: str | None,
                         path: str, method: str, actor_id: str | None,
                         subject_type: str = "scan_job", subject_id: str | None = None,
                         short_circuit: bool = True, mode: str = sp.MODE_LIVE,
                         exclude_job_id: Any | None = None
                         ) -> tuple[sp.ScopeDecisionResult, models.ScopeDecision]:
    req = build_scope_request(session, asset=asset, profile_key=profile_key, path=path,
                              method=method, subject_type=subject_type, mode=mode,
                              exclude_job_id=exclude_job_id)
    result = sp.evaluate(req, short_circuit=short_circuit)
    row = persist_decision(session, result, subject_type=subject_type, subject_id=subject_id,
                           asset_id=asset.id if asset else None, actor_kind="human",
                           actor_id=actor_id)
    audit.record(session, action="scope_decision", actor_kind="human", actor_id=actor_id,
                 outcome=result.decision, subject_type=subject_type,
                 subject_id=subject_id or (str(asset.id) if asset else None),
                 detail={"policy_version": result.policy_version, "mode": result.mode,
                         "first_failure": (result.first_failure.gate if result.first_failure else None),
                         "scope_decision_id": str(row.id)})
    return result, row


# ------------------------------------------------------------------- jobs -----
def create_job(session: Session, *, asset: models.Asset, profile_key: str, actor_id: str,
               trace: str, idempotency_key: str | None,
               mode: str = sp.MODE_LIVE) -> models.ScanJob:
    """Create a job ONLY on an allow decision. A denial raises 409 with the
    ordered gate results, and the denial itself is persisted and audited."""
    if idempotency_key:
        existing = session.execute(select(models.ScanJob).where(
            models.ScanJob.idempotency_key == idempotency_key)).scalar_one_or_none()
        if existing is not None:
            return existing
    profile_row = session.execute(select(models.ScanProfile).where(
        models.ScanProfile.key == profile_key)).scalar_one_or_none()
    if profile_row is None:
        raise errors.bad_request(f"unknown scan profile {profile_key!r}")
    if mode == sp.MODE_FIXTURE and profile_row.adapter_name != "mock":
        # Fixture mode exists because the mock adapter contacts nothing. An
        # adapter that touches the target may only ever run in live mode.
        raise errors.conflict(
            "fixture-mode-requires-mock-adapter", "Fixture mode requires the mock adapter",
            f"profile {profile_key!r} uses the {profile_row.adapter_name!r} adapter, which "
            "contacts the target; it may only run in live mode under the full gate chain")
    if mode == sp.MODE_FIXTURE and (profile_row.is_intrusive or profile_row.active_scan):
        raise errors.conflict("fixture-mode-not-intrusive", "Fixture mode cannot be intrusive",
                              "an intrusive or active profile may only run in live mode")
    result, decision_row = evaluate_and_persist(
        session, asset=asset, profile_key=profile_key, path=asset.base_path or "/",
        method="GET", actor_id=actor_id, mode=mode)
    if not result.allowed:
        session.commit()
        failure = result.first_failure
        raise errors.conflict("scope-denied", "Assessment request denied by scope policy",
                              f"Gate {failure.gate!r} failed" if failure
                              else "a gate denied the request",
                              {"scope_decision": result.as_dict()})
    profile = profile_row
    grant = active_grant(session, asset.id)
    job = models.ScanJob(
        asset_id=asset.id, scope_grant_id=(grant.id if grant else None),
        profile_key=profile_key, state="queued", phase="preflight", mode=mode,
        idempotency_key=idempotency_key, adapter_name=settings().default_scanner_adapter,
        scope_decision_id=decision_row.id, pinned_ips=list(result.resolved_ips),
        trace_id=trace, created_by=actor_id,
        queued_at=dt.datetime.now(dt.timezone.utc),
        budget_snapshot={"max_requests_per_second": profile.max_requests_per_second,
                         "max_total_requests": profile.max_total_requests,
                         "max_duration_seconds": profile.max_duration_seconds})
    session.add(job)
    session.flush()
    session.add(models.ScanJobEvent(job_id=job.id, to_state="queued", phase="preflight",
                                    message="job accepted after an allow ScopeDecision"))
    audit.record(session, action="scan_job_created", actor_kind="human", actor_id=actor_id,
                 outcome="ok", subject_type="scan_job", subject_id=str(job.id), trace_id=trace,
                 detail={"profile_key": profile_key, "pinned_ips": list(result.resolved_ips)})
    return job


def enqueue_job(job: models.ScanJob) -> bool:
    """Hand the job to the worker. A broker failure leaves it `queued`."""
    try:
        from .worker.tasks import run_assessment
        run_assessment.apply_async(args=[str(job.id)], queue="vapt")
        return True
    except Exception:                                      # noqa: BLE001
        return False
