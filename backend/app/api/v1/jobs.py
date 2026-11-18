"""Assessment job management. A job exists only after an allow ScopeDecision."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Header
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import errors, models, schemas, services
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


@router.post("/assets/{asset_id}/assessments", response_model=schemas.JobOut, status_code=201)
def create_assessment(asset_id: str, payload: schemas.JobCreate,
                      session: Session = Depends(get_session),
                      p: Principal = Depends(require_role("analyst")),
                      trace: str = Depends(trace_id),
                      idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    job = services.create_job(session, asset=asset, profile_key=payload.profile_key,
                              actor_id=p.id, trace=trace, idempotency_key=idempotency_key)
    session.commit()
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
