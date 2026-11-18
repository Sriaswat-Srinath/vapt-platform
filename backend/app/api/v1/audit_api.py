"""Audit log reading and chain verification."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import audit, models
from ...db import get_session
from ...deps import Principal, require_role

router = APIRouter()


@router.get("/audit")
def list_audit(limit: int = Query(default=50, le=200), subject_type: str | None = None,
               session: Session = Depends(get_session),
               p: Principal = Depends(require_role("approver"))):
    stmt = select(models.AuditLog).order_by(models.AuditLog.seq.desc()).limit(limit)
    if subject_type:
        stmt = stmt.where(models.AuditLog.subject_type == subject_type)
    rows = session.execute(stmt).scalars().all()
    return [{"seq": r.seq, "occurred_at": r.occurred_at, "actor_kind": r.actor_kind,
             "actor_id": r.actor_id, "action": r.action, "subject_type": r.subject_type,
             "subject_id": r.subject_id, "outcome": r.outcome, "detail": r.detail,
             "entry_hash": r.entry_hash} for r in rows]


@router.get("/audit/verify")
def verify_chain(session: Session = Depends(get_session),
                 p: Principal = Depends(require_role("admin"))):
    return audit.verify(session)
