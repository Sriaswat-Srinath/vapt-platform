"""API tokens: opaque, Argon2-hashed, role-bearing."""
from __future__ import annotations
import datetime as dt
import secrets
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy.orm import Session
from . import models

_ph = PasswordHasher()
PREFIX = "vapt"


def issue_token(session: Session, analyst: models.Analyst, label: str,
                ttl_days: int | None = 90) -> tuple[models.ApiToken, str]:
    """Returns the row and the ONLY copy of the plaintext token."""
    secret = secrets.token_urlsafe(32)
    row = models.ApiToken(
        analyst_id=analyst.id,
        token_hash=_ph.hash(secret),
        label=label,
        expires_at=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=ttl_days)) if ttl_days else None,
    )
    session.add(row)
    session.flush()
    return row, f"{PREFIX}_{row.id}_{secret}"


def authenticate(session: Session, presented: str) -> tuple[models.Analyst, models.ApiToken] | None:
    try:
        prefix, token_id, secret = presented.split("_", 2)
    except ValueError:
        return None
    if prefix != PREFIX:
        return None
    try:
        tid = uuid.UUID(token_id)
    except ValueError:
        return None
    row = session.get(models.ApiToken, tid)
    if row is None or row.revoked_at is not None:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    if row.expires_at is not None and row.expires_at <= now:
        return None
    try:
        _ph.verify(row.token_hash, secret)
    except (VerifyMismatchError, VerificationError):
        return None
    analyst = session.get(models.Analyst, row.analyst_id)
    if analyst is None or not analyst.is_active:
        return None
    row.last_used_at = now
    return analyst, row
