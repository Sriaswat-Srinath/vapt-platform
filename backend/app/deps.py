"""Request dependencies: auth, roles, trace ids."""
from __future__ import annotations
import uuid
from dataclasses import dataclass
from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session
from . import errors, models, security
from .db import get_session


@dataclass(frozen=True)
class Principal:
    analyst: models.Analyst
    token: models.ApiToken

    @property
    def id(self) -> str:
        return str(self.analyst.id)

    @property
    def role(self) -> str:
        return self.analyst.role


def trace_id(request: Request) -> str:
    existing = request.headers.get("x-vapt-trace")
    return existing[:64] if existing else uuid.uuid4().hex[:32]


def principal(authorization: str | None = Header(default=None),
              session: Session = Depends(get_session)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise errors.unauthorized()
    result = security.authenticate(session, authorization.split(" ", 1)[1].strip())
    if result is None:
        raise errors.unauthorized("Token is invalid, expired or revoked")
    session.commit()
    return Principal(*result)


def require_role(*roles: str):
    def _dep(p: Principal = Depends(principal)) -> Principal:
        # admin is a superset of approver for decision-making purposes
        allowed = set(roles) | ({"admin"} if roles else set())
        if p.role not in allowed:
            raise errors.forbidden(f"role {p.role!r} may not perform this action; "
                                   f"requires one of {sorted(allowed)}")
        return p
    return _dep
