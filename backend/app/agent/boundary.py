"""Stage 2 of the redaction boundary: what may cross to an LLM.

Stage 1 (evidence/redaction.py) redacts on write. Stage 2 runs again here, on
the way out, and then ASSERTS. The assertion is the point: a redaction bug
upstream must stop the request rather than be carried over the boundary by a
component that trusted it.

Three rules, enforced in code rather than in a prompt:

  I5   no unredacted evidence leaves. Every string is re-redacted on the way
       out, and if that second pass removes ANYTHING, stage 1 missed it and the
       request is refused rather than sent.
  I11  no plain hash of a secret value crosses. Correlation refs are keyed
       HMACs (`ref=hmac:<key_id>:…`); a bare hex digest of 32+ characters in an
       outbound payload is refused on sight.
  --   nothing identifies this deployment: no tokens, no connection strings, no
       internal addresses beyond the lab target the report already names.

A refusal here is a FAILURE of the caller, never a reason to send anyway.
"""
from __future__ import annotations
import dataclasses as dc
import re

from ..evidence import redaction

BOUNDARY_VERSION = "1.0.0"

# A bare digest: 32+ hex characters not preceded by the keyed-ref marker.
BARE_DIGEST = re.compile(r"(?<!hmac:)(?<![a-zA-Z0-9:])[0-9a-f]{32,}(?![a-zA-Z0-9])")
KEYED_REF = re.compile(r"ref=hmac:[A-Za-z0-9_.-]+:[A-Z2-7]+")
# Deployment-identifying material that must never be described to a model.
FORBIDDEN = (
    re.compile(r"vapt_[0-9a-f-]{8,}", re.I),                    # api tokens
    re.compile(r"postgresql(\+\w+)?://", re.I),                  # connection strings
    re.compile(r"redis://", re.I),
    re.compile(r"\b172\.30\.(2[0-3])\.\d{1,3}\b"),               # application plane
    re.compile(r"-----BEGIN [A-Z ]+-----"),
)


class BoundaryRefusal(RuntimeError):
    """Raised instead of sending. Carries the rule that refused it."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


@dc.dataclass(frozen=True, slots=True)
class BoundaryReport:
    checked_fields: int
    re_redacted_fields: int
    keyed_refs: int
    boundary_version: str
    redaction_version: str

    def as_dict(self) -> dict[str, object]:
        return dc.asdict(self)


# Keys whose values this platform GENERATES: catalogue keys, taxonomy keys,
# rule ids, opaque handles, enum-ish labels. They are exempt from the
# round-trip check only — a long hyphenated identifier such as
# `missing-security-header-content-type-options` looks like a high-entropy blob
# to the redactor, and refusing it would stop every request for no gain.
#
# The list is an EXEMPTION list, not an allowlist: anything not named here is
# treated as target-derived and must survive a redaction round trip, so a field
# added later is strict by default. The forbidden-material and bare-digest
# checks apply to every string regardless.
STRUCTURAL_KEYS = frozenset({
    "finding_id", "catalogue_key", "category", "taxonomy_key", "validation_rule_id",
    "validation_state", "severity", "detection", "priority", "tier", "key", "name",
    "concern", "surface", "tool", "fields", "prompt_version", "environment",
    "identifier", "blocked_by", "candidates", "findings", "requires_citations",
    "coverage_complete", "instruction", "summary",
})


def _walk(node: object, path: str = "$", key: str | None = None):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}", k)
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]", key)
    else:
        yield path, key, node


def enforce(payload: dict) -> tuple[dict, BoundaryReport]:
    """Re-redact and verify. Returns the payload to send, or refuses.

    Pure: it does not send anything and has no I/O. The transport calls it and
    may not send a payload it has not been returned by this function.
    """
    checked = re_redacted = refs = 0
    for path, key, value in _walk(payload):
        if not isinstance(value, str):
            continue
        checked += 1
        refs += len(KEYED_REF.findall(value))
        for pattern in FORBIDDEN:
            if pattern.search(value):
                raise BoundaryRefusal(
                    "deployment-identifying material",
                    f"{path} contains a value matching {pattern.pattern!r}")
        bare = BARE_DIGEST.search(value)
        if bare:
            raise BoundaryRefusal(
                "I11 plain digest",
                f"{path} contains a bare {len(bare.group(0))}-character digest. Correlation must "
                "use a keyed HMAC ref, never a hash of the value itself.")
        # The test is "does a second pass REMOVE anything", not "is the output
        # byte-identical": redaction also normalises trailing whitespace, and a
        # stripped newline is not a leak. The report's counts are the evidence.
        if key in STRUCTURAL_KEYS:
            continue
        _again, report = redaction.redact(value)
        if report.counts:
            re_redacted += 1
            raise BoundaryRefusal(
                "I5 unredacted evidence",
                f"{path} still contained material that redaction removes on a second pass "
                f"({dict(report.counts)}). Stage 1 missed it; the request is refused rather "
                "than sent.")
    return payload, BoundaryReport(checked, re_redacted, refs, BOUNDARY_VERSION,
                                   redaction.REDACTION_VERSION)


def is_safe(payload: dict) -> bool:
    """Convenience for tests and callers that want a boolean, not an exception."""
    try:
        enforce(payload)
    except BoundaryRefusal:
        return False
    return True
