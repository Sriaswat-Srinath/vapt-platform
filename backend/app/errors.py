"""RFC 9457 problem+json error model."""
from __future__ import annotations
from typing import Any
from fastapi import HTTPException

BASE = "https://vapt.local/problems/"


class Problem(HTTPException):
    def __init__(self, status: int, slug: str, title: str, detail: str | None = None,
                 extra: dict[str, Any] | None = None):
        super().__init__(status_code=status, detail=detail or title)
        self.slug, self.title, self.extra = slug, title, extra or {}

    def body(self, trace_id: str | None) -> dict[str, Any]:
        return {"type": BASE + self.slug, "title": self.title, "status": self.status_code,
                "detail": self.detail, "trace_id": trace_id, **self.extra}


def not_found(what: str) -> Problem:
    return Problem(404, "not-found", f"{what} not found")


def conflict(slug: str, title: str, detail: str, extra: dict[str, Any] | None = None) -> Problem:
    return Problem(409, slug, title, detail, extra)


def forbidden(detail: str) -> Problem:
    return Problem(403, "forbidden", "Forbidden", detail)


def unauthorized(detail: str = "A valid bearer token is required") -> Problem:
    return Problem(401, "unauthorized", "Unauthorized", detail)


def bad_request(detail: str, slug: str = "invalid-request") -> Problem:
    return Problem(400, slug, "Invalid request", detail)


def precondition_failed(detail: str) -> Problem:
    return Problem(412, "precondition-failed", "Precondition failed", detail)
