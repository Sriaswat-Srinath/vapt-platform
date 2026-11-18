"""Append-only, hash-chained audit log.

entry_hash = sha256(prev_hash || canonical_json(entry)). The chain makes
tampering detectable: `GET /api/v1/audit/verify` recomputes it and reports the
first divergence. The application never UPDATEs or DELETEs these rows.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from . import models

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode()).hexdigest()


def record(session: Session, *, action: str, actor_kind: str, actor_id: str | None,
           outcome: str, subject_type: str | None = None, subject_id: str | None = None,
           detail: dict[str, Any] | None = None, trace_id: str | None = None) -> models.AuditLog:
    last = session.execute(
        select(models.AuditLog).order_by(models.AuditLog.seq.desc()).limit(1)
    ).scalar_one_or_none()
    prev = last.entry_hash if last else GENESIS
    occurred_at = dt.datetime.now(dt.timezone.utc)
    payload = {
        "occurred_at": occurred_at.isoformat(), "actor_kind": actor_kind, "actor_id": actor_id,
        "action": action, "subject_type": subject_type, "subject_id": subject_id,
        "outcome": outcome, "detail": detail, "trace_id": trace_id,
    }
    row = models.AuditLog(occurred_at=occurred_at, trace_id=trace_id, actor_kind=actor_kind,
                          actor_id=actor_id, action=action, subject_type=subject_type,
                          subject_id=subject_id, outcome=outcome, detail=detail,
                          prev_hash=prev, entry_hash=entry_hash(prev, payload))
    session.add(row)
    session.flush()
    return row


def verify(session: Session) -> dict[str, Any]:
    rows = session.execute(select(models.AuditLog).order_by(models.AuditLog.seq.asc())).scalars().all()
    prev = GENESIS
    for row in rows:
        payload = {
            "occurred_at": row.occurred_at.isoformat(), "actor_kind": row.actor_kind,
            "actor_id": row.actor_id, "action": row.action, "subject_type": row.subject_type,
            "subject_id": row.subject_id, "outcome": row.outcome, "detail": row.detail,
            "trace_id": row.trace_id,
        }
        expected = entry_hash(prev, payload)
        if row.prev_hash != prev or row.entry_hash != expected:
            return {"ok": False, "entries": len(rows), "first_divergence": {
                "id": str(row.id), "seq": row.seq, "expected_entry_hash": expected,
                "stored_entry_hash": row.entry_hash}}
        prev = row.entry_hash
    return {"ok": True, "entries": len(rows), "head": prev}
