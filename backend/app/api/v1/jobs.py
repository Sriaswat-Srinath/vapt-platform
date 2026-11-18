"""Assessment job management. A job exists only after an allow ScopeDecision."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
import datetime as dt
from ... import audit, errors, models, schemas, services
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


@router.post("/assets/{asset_id}/assessments", response_model=schemas.JobOut, status_code=201)
def create_assessment(asset_id: str, payload: schemas.JobCreate,
                      mode: str = Query(default="live", pattern="^(fixture|live)$"),
                      session: Session = Depends(get_session),
                      p: Principal = Depends(require_role("analyst")),
                      trace: str = Depends(trace_id),
                      idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    job = services.create_job(session, asset=asset, profile_key=payload.profile_key,
                              actor_id=p.id, trace=trace, idempotency_key=idempotency_key,
                              mode=mode)
    session.commit()
    services.enqueue_job(job)
    return job


@router.get("/assessments", response_model=list[schemas.JobOut])
def list_assessments(asset_id: str | None = None, session: Session = Depends(get_session),
                     p: Principal = Depends(require_role("analyst", "approver"))):
    stmt = select(models.ScanJob).order_by(models.ScanJob.created_at.desc())
    if asset_id:
        stmt = stmt.where(models.ScanJob.asset_id == asset_id)
    return session.execute(stmt).scalars().all()


@router.get("/assessments/{job_id}", response_model=schemas.JobOut)
def get_assessment(job_id: str, session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst", "approver"))):
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise errors.not_found("Assessment")
    return job


@router.get("/assessments/{job_id}/events")
def assessment_events(job_id: str, session: Session = Depends(get_session),
                      p: Principal = Depends(require_role("analyst", "approver"))):
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise errors.not_found("Assessment")
    rows = session.execute(select(models.ScanJobEvent).where(
        models.ScanJobEvent.job_id == job_id).order_by(models.ScanJobEvent.at)).scalars().all()
    return [{"at": r.at, "from_state": r.from_state, "to_state": r.to_state,
             "phase": r.phase, "message": r.message} for r in rows]


@router.get("/assessments/{job_id}/scope-decision")
def assessment_decision(job_id: str, session: Session = Depends(get_session),
                        p: Principal = Depends(require_role("analyst", "approver"))):
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise errors.not_found("Assessment")
    row = session.get(models.ScopeDecision, job.scope_decision_id) if job.scope_decision_id else None
    if row is None:
        raise errors.not_found("Scope decision")
    return {"id": str(row.id), "policy_version": row.policy_version, "decision": row.decision,
            "resolved_ips": row.resolved_ips, **row.gate_results}


@router.post("/assessments/{job_id}/cancel", response_model=schemas.JobOut)
def cancel_assessment(job_id: str, session: Session = Depends(get_session),
                      p: Principal = Depends(require_role("analyst")),
                      trace: str = Depends(trace_id)):
    """Request cancellation. The worker observes it at its next checkpoint;
    total latency is bounded by CANCELLATION_SLA_SECONDS (ADR-0008 R3 §14)."""
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise errors.not_found("Assessment")
    if job.state in ("completed", "failed", "cancelled", "blocked"):
        raise errors.conflict("already-terminal", "Assessment already finished",
                              f"the assessment is {job.state!r} and cannot be cancelled")
    job.cancel_requested_at = dt.datetime.now(dt.timezone.utc)
    audit.record(session, action="assessment_cancel_requested", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scan_job", subject_id=str(job.id), trace_id=trace)
    session.commit()
    return job


@router.get("/assessments/{job_id}/raw-observations")
def raw_observations(job_id: str, limit: int = 50, session: Session = Depends(get_session),
                     p: Principal = Depends(require_role("analyst", "approver"))):
    """Verbatim scanner output with provenance. Immutable: the database refuses
    updates and deletes (ADR-0002)."""
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise errors.not_found("Assessment")
    rows = session.execute(select(models.RawObservation).where(
        models.RawObservation.job_id == job_id).order_by(
        models.RawObservation.captured_at).limit(min(limit, 200))).scalars().all()
    rejected = session.execute(select(models.IngestionRejection).where(
        models.IngestionRejection.job_id == job_id)).scalars().all()
    return {
        "job_id": str(job_id), "stored": len(rows), "rejected_at_ingestion": len(rejected),
        "rejections": [{"reason": r.reason, "observed_url": r.observed_url} for r in rejected],
        "observations": [{"id": str(r.id), "adapter": r.adapter_name,
                          "adapter_version": r.adapter_version, "rule_id": r.adapter_rule_id,
                          "observed_url": r.observed_url, "payload_sha256": r.payload_sha256,
                          "request_sha256": r.request_sha256,
                          "response_sha256": r.response_sha256,
                          "captured_at": r.captured_at,
                          "payload": r.payload} for r in rows],
    }


@router.post("/assessments/{job_id}/revalidate")
def revalidate(job_id: str, session: Session = Depends(get_session),
               p: Principal = Depends(require_role("analyst")),
               trace: str = Depends(trace_id)):
    """Re-run normalisation and the deterministic validation engine over the
    stored observations.

    Possible because raw observations are immutable and the pipeline is a
    function of stored inputs (ADR-0002): an improved mapper or rule pack can be
    applied to a historical assessment, and the delta is recorded as new
    validation events. The engine is the only actor; no LLM is involved.
    """
    job = session.get(models.ScanJob, job_id)
    if job is None:
        raise errors.not_found("Assessment")
    asset = session.get(models.Asset, job.asset_id)
    # Revalidation re-reads the stored bytes. If retention has purged any of
    # them, the inputs are no longer the inputs the original verdict was based
    # on, and re-running would quietly produce a DIFFERENT verdict from LESS
    # evidence. Refuse instead.
    purged = session.execute(select(func.count()).select_from(models.RawObservation)
                             .join(models.EvidenceBlob,
                                   (models.EvidenceBlob.id == models.RawObservation.request_blob_id) |
                                   (models.EvidenceBlob.id == models.RawObservation.response_blob_id))
                             .where(models.RawObservation.job_id == job.id,
                                    models.EvidenceBlob.state != "present")).scalar_one()
    if purged:
        raise errors.conflict(
            "evidence-purged",
            "This assessment's evidence has been purged",
            f"{purged} stored request/response blob(s) are no longer present, so revalidation "
            "would reach a verdict from less evidence than the original. The existing findings "
            "and their provenance digests remain.")
    from ...findings_pipeline import process_job
    stats = process_job(session, job, asset)
    audit.record(session, action="assessment_revalidated", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scan_job", subject_id=str(job.id), trace_id=trace,
                 detail=stats)
    session.commit()
    return {"job_id": str(job.id), "coverage_complete": job.coverage_complete, "stats": stats}
