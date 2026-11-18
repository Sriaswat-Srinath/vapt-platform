"""Deterministic evidence validation.

A scanner alert is not a vulnerability. This module decides between
candidate / confirmed / false_positive / inconclusive / not_applicable by
evaluating predicates over STORED EVIDENCE ONLY. It is pure: no I/O, no ORM, no
model. Every outcome names the rule and version that produced it and the inputs
it used, so the decision is reproducible and explainable (ADR-0003).

Soundness rule that matters most (ADR-0008 R3 §13): NEGATIVE evidence — "this
header was absent everywhere we looked" — is meaningless when collection was
truncated. When `coverage_complete` is false, negative-evidence rules resolve to
`inconclusive` rather than `confirmed`.

Nothing here consults an LLM, and the agent cannot reach this module.
"""
from __future__ import annotations
import dataclasses as dc

RULES_VERSION = "1.1.0"

CANDIDATE = "candidate"
CONFIRMED = "confirmed"
FALSE_POSITIVE = "false_positive"
INCONCLUSIVE = "inconclusive"
NOT_APPLICABLE = "not_applicable"

# A missing-header claim is only confirmed with enough independent sightings.
MIN_RESPONSES = 1
MIN_DISTINCT_URLS = 1
BROWSER_CONTENT_TYPES = ("text/html", "application/xhtml")


@dc.dataclass(frozen=True, slots=True)
class ValidationInputs:
    """Everything a rule may look at. Immutable and explicit."""
    evidence_class: str
    coverage_complete: bool
    # response facts
    status_codes: tuple[int, ...] = ()
    content_types: tuple[str, ...] = ()
    distinct_urls: int = 0
    response_count: int = 0
    header_present_count: int = 0
    header_absent_count: int = 0
    # body / reflection facts
    scanner_evidence: str | None = None
    evidence_found_in_body: bool = False
    reflected_unencoded: bool = False
    html_context: bool = False
    has_request_evidence: bool = False
    has_response_evidence: bool = False
    confidence: str = "low"
    # cookie facts (session management). Attribute NAMES only; a cookie's value
    # is never read, stored or reasoned about.
    set_cookie_count: int = 0
    cookie_attributes_present: tuple[str, ...] = ()
    cookie_attribute_claimed_missing: str | None = None
    transport_is_cleartext: bool = False


@dc.dataclass(frozen=True, slots=True)
class ValidationOutcome:
    state: str
    rule_id: str
    rule_version: str
    reason: str
    inputs: dict[str, object]

    def as_dict(self) -> dict[str, object]:
        return {"state": self.state, "rule_id": self.rule_id,
                "rule_version": self.rule_version, "reason": self.reason,
                "inputs": self.inputs}


def _inputs_dict(i: ValidationInputs) -> dict[str, object]:
    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in dc.asdict(i).items()}


def _browser_reachable(i: ValidationInputs) -> bool:
    return any(ct and any(ct.lower().startswith(b) for b in BROWSER_CONTENT_TYPES)
               for ct in i.content_types)


def _rule_missing_header(i: ValidationInputs) -> ValidationOutcome:
    rid = "missing-security-header"
    base = _inputs_dict(i)
    if not i.has_response_evidence:
        return ValidationOutcome(CANDIDATE, rid, RULES_VERSION,
                                 "no stored response evidence yet: the evidence gap is recorded",
                                 base)
    if not _browser_reachable(i):
        return ValidationOutcome(NOT_APPLICABLE, rid, RULES_VERSION,
                                 "the endpoint is not browser-reachable HTML, so a browser "
                                 "security header does not apply", base)
    if i.header_present_count > 0 and i.header_absent_count > 0:
        return ValidationOutcome(INCONCLUSIVE, rid, RULES_VERSION,
                                 f"the header is present on {i.header_present_count} response(s) "
                                 f"and absent on {i.header_absent_count}", base)
    if i.header_present_count > 0:
        return ValidationOutcome(FALSE_POSITIVE, rid, RULES_VERSION,
                                 "the header is present in the stored evidence", base)
    # Negative evidence: only sound under complete coverage.
    if not i.coverage_complete:
        return ValidationOutcome(INCONCLUSIVE, rid, RULES_VERSION,
                                 "absence cannot be confirmed from truncated collection "
                                 "(coverage_complete=false)", base)
    if i.response_count >= MIN_RESPONSES and i.distinct_urls >= MIN_DISTINCT_URLS:
        return ValidationOutcome(CONFIRMED, rid, RULES_VERSION,
                                 f"absent across {i.response_count} successful response(s) on "
                                 f"{i.distinct_urls} distinct URL(s) with complete coverage", base)
    return ValidationOutcome(CANDIDATE, rid, RULES_VERSION,
                             "not enough independent sightings to confirm absence", base)


def _rule_header_value(i: ValidationInputs) -> ValidationOutcome:
    rid = "header-value-directive"
    base = _inputs_dict(i)
    if not i.has_response_evidence:
        return ValidationOutcome(CANDIDATE, rid, RULES_VERSION, "no stored response evidence", base)
    if not _browser_reachable(i):
        return ValidationOutcome(NOT_APPLICABLE, rid, RULES_VERSION,
                                 "not browser-reachable HTML", base)
    if i.scanner_evidence:
        return ValidationOutcome(CONFIRMED, rid, RULES_VERSION,
                                 f"the directive {i.scanner_evidence!r} is present in the stored "
                                 "response headers", base)
    return ValidationOutcome(INCONCLUSIVE, rid, RULES_VERSION,
                             "the scanner reported no header value to check against", base)


def _rule_pattern_in_body(i: ValidationInputs) -> ValidationOutcome:
    rid = "pattern-in-body"
    base = _inputs_dict(i)
    if not i.has_response_evidence:
        return ValidationOutcome(CANDIDATE, rid, RULES_VERSION, "no stored response evidence", base)
    if not i.scanner_evidence:
        return ValidationOutcome(INCONCLUSIVE, rid, RULES_VERSION,
                                 "the scanner reported no evidence string to locate", base)
    if i.evidence_found_in_body:
        return ValidationOutcome(CONFIRMED, rid, RULES_VERSION,
                                 f"the reported evidence {i.scanner_evidence!r} is present in the "
                                 "stored response body", base)
    return ValidationOutcome(FALSE_POSITIVE, rid, RULES_VERSION,
                             f"the reported evidence {i.scanner_evidence!r} is NOT present in the "
                             "stored response body", base)


def _rule_reflected_input(i: ValidationInputs) -> ValidationOutcome:
    rid = "reflected-input"
    base = _inputs_dict(i)
    if not (i.has_request_evidence and i.has_response_evidence):
        return ValidationOutcome(CANDIDATE, rid, RULES_VERSION,
                                 "a reflection claim needs both the request and the response", base)
    if not i.evidence_found_in_body:
        return ValidationOutcome(FALSE_POSITIVE, rid, RULES_VERSION,
                                 "the payload is not reflected in the stored response", base)
    if not i.html_context:
        return ValidationOutcome(INCONCLUSIVE, rid, RULES_VERSION,
                                 "reflected, but not in an HTML context", base)
    if i.reflected_unencoded:
        # Presence does not depend on coverage, so this may confirm regardless.
        return ValidationOutcome(CONFIRMED, rid, RULES_VERSION,
                                 "the payload is reflected unencoded in an HTML context", base)
    return ValidationOutcome(FALSE_POSITIVE, rid, RULES_VERSION,
                             "reflected, but encoded in the response", base)


def _rule_cookie_attribute(i: ValidationInputs) -> ValidationOutcome:
    """Session-management rule pack (1.1.0).

    A cookie attribute is wholly contained in a response the platform has
    already stored, so the claim is decidable without sending anything. The
    rule reads attribute NAMES only — never a cookie value.
    """
    rid = "cookie-attribute"
    base = _inputs_dict(i)
    attr = i.cookie_attribute_claimed_missing
    if not i.has_response_evidence:
        return ValidationOutcome(CANDIDATE, rid, RULES_VERSION,
                                 "no stored response evidence yet", base)
    if not attr:
        return ValidationOutcome(INCONCLUSIVE, rid, RULES_VERSION,
                                 "the scanner named no cookie attribute to check", base)
    if i.set_cookie_count == 0:
        return ValidationOutcome(FALSE_POSITIVE, rid, RULES_VERSION,
                                 "the stored response sets no cookie, so no cookie attribute can "
                                 "be missing from it", base)
    present = {a.lower() for a in i.cookie_attributes_present}
    if attr.lower() in present:
        return ValidationOutcome(FALSE_POSITIVE, rid, RULES_VERSION,
                                 f"the stored Set-Cookie carries {attr}", base)
    if attr.lower() == "secure" and i.transport_is_cleartext:
        # Honest, and it keeps a plain-HTTP lab from generating noise that a
        # reader would have to discount by hand.
        return ValidationOutcome(NOT_APPLICABLE, rid, RULES_VERSION,
                                 "the target is served over cleartext HTTP, where Secure would "
                                 "prevent the cookie being sent at all; the transport itself is "
                                 "the finding", base)
    return ValidationOutcome(CONFIRMED, rid, RULES_VERSION,
                             f"the stored Set-Cookie does not carry {attr} "
                             f"(present: {sorted(present) or 'none'})", base)


def _rule_unmapped(i: ValidationInputs) -> ValidationOutcome:
    return ValidationOutcome(CANDIDATE, "unmapped-detection", RULES_VERSION,
                             "no validation rule covers this scanner rule; the detection is kept "
                             "and surfaced as an unmapped detection rather than dropped",
                             _inputs_dict(i))


RULE_PACKS = {
    "missing_header": _rule_missing_header,
    "header_value": _rule_header_value,
    "pattern_in_body": _rule_pattern_in_body,
    "reflected_input": _rule_reflected_input,
    "cookie_attribute": _rule_cookie_attribute,
    "missing_form_token": _rule_unmapped,
    "unmapped": _rule_unmapped,
}


def classify(inputs: ValidationInputs) -> ValidationOutcome:
    """Total: an unknown evidence class is a candidate, never a confirmation."""
    rule = RULE_PACKS.get(inputs.evidence_class)
    if rule is None:
        return _rule_unmapped(inputs)
    try:
        return rule(inputs)
    except Exception as exc:                               # noqa: BLE001 - fail safe
        return ValidationOutcome(CANDIDATE, f"{inputs.evidence_class}-error", RULES_VERSION,
                                 f"rule raised {type(exc).__name__}: {exc}", _inputs_dict(inputs))
