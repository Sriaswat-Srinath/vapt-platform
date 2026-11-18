"""CVSS attachment. Parse-and-validate only — never invent.

CVSS comes from the curated catalogue. The MVP deliberately computes NO
prioritisation score: those columns stay null rather than carrying a premature
formula (MVP_SCOPE.md reconciliation of ADR-0004). EPSS and KEV are absent, so
they are null — never estimated.
"""
from __future__ import annotations
import dataclasses as dc
import re

VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
                       r"C:[NLH]/I:[NLH]/A:[NLH])$")


@dc.dataclass(frozen=True, slots=True)
class CvssAttachment:
    source: str | None
    version: str | None
    vector: str | None
    base: float | None
    valid: bool
    reason: str


def attach_from_catalogue(*, version: str | None, vector: str | None,
                          base: float | None) -> CvssAttachment:
    if not vector and base is None:
        return CvssAttachment(None, None, None, None, False,
                              "the catalogue entry carries no CVSS; the column stays null")
    if vector and not VECTOR_RE.match(vector):
        return CvssAttachment(None, None, None, None, False,
                              f"refusing a malformed CVSS vector {vector!r}")
    if base is not None and not (0.0 <= float(base) <= 10.0):
        return CvssAttachment(None, None, None, None, False,
                              f"refusing an out-of-range CVSS base score {base!r}")
    return CvssAttachment("catalogue", version or "3.1", vector,
                          float(base) if base is not None else None, True,
                          "CVSS taken from the curated catalogue")
