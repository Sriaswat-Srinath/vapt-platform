"""Parsing model output into proposals. Dependency-free and pure.

Separate from the runner because this is the code that handles UNTRUSTED input
from outside the platform: it must be testable without a database, a container
or a network, and it must never raise on malformed input — a model that returns
prose is a normal Tuesday, not an exception.
"""
from __future__ import annotations
import json

from . import tools


def parse_proposals(text: str, *, known_finding_ids: set[str]) -> tuple[list[dict], list[dict]]:
    """Returns (accepted, rejected). Never raises on model output.

    `known_finding_ids` are the HANDLES that were actually sent, so a model
    cannot cite anything it was not given.

    A model that returns prose, invalid JSON, or a tool outside the catalogue
    produces rejections — which are stored, because a silent drop would hide
    exactly the behaviour worth watching.
    """
    accepted: list[dict] = []
    rejected: list[dict] = []
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        doc = json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError) as exc:
        return [], [{"reason": "unparseable", "detail": f"{type(exc).__name__}: {exc}",
                     "raw_excerpt": text[:300]}]
    raw = doc.get("proposals")
    if not isinstance(raw, list):
        return [], [{"reason": "malformed", "detail": "no `proposals` array in the response",
                     "raw_excerpt": text[:300]}]
    for item in raw[:20]:
        try:
            accepted.append(tools.validate(item, known_finding_ids=known_finding_ids))
        except tools.ProposalRejected as exc:
            rejected.append({"reason": exc.reason, "detail": exc.detail,
                             "tool": (item or {}).get("tool") if isinstance(item, dict) else None})
    return accepted, rejected
