"""The vulnerability taxonomy: tiers, priorities and what the platform can
currently assert about each category.

This is FIRST-CLASS DATA, not a label on a finding. Every category exists in
the table whether or not the platform can detect it, so coverage — including
the zeroes — is measurable rather than implied. Two separate questions are
kept apart deliberately:

  * `tier` / `priority`  — what the OWNER says matters, and in what order.
  * `detection`          — what THIS BUILD can actually assert, derived at
                           query time from catalogue entries and rule packs.

A category with priority `critical` and no detection capability is the most
important row in the table, and the one a report must not let a reader miss.
"""
from __future__ import annotations
import dataclasses as dc

TAXONOMY_VERSION = "1.0.0"

# Assertability describes what evidence a category needs, independently of
# whether this build has the rule yet. It is what makes the gap honest:
# `active` categories cannot be confirmed passively by anyone, ever.
PASSIVE = "passive"          # confirmable from observed traffic alone
ACTIVE = "active"            # needs crafted requests: intrusive, dual control
MANUAL = "manual"            # needs human judgement; no automated confirmation


@dc.dataclass(frozen=True, slots=True)
class Category:
    key: str
    display_name: str
    tier: int
    priority: str
    assertability: str
    owasp_2021: str | None
    description: str
    sort_index: int


def _c(i: int, key: str, name: str, tier: int, prio: str, assertability: str,
       owasp: str | None, desc: str) -> Category:
    return Category(key, name, tier, prio, assertability, owasp, desc, i)


# Tier 1 — the MVP set, in the owner's priority order.
TIER1: tuple[Category, ...] = (
    _c(1, "broken_access_control", "Broken Access Control", 1, "critical", ACTIVE, "A01",
       "Authorisation that can be bypassed: object references that are not checked, "
       "paths reachable without the role they require, cross-user data access."),
    _c(2, "authentication", "Authentication", 1, "critical", ACTIVE, "A07",
       "Weaknesses in how identity is proven: credential handling, recovery flows, "
       "enumeration, and transport of secrets. Credential guessing is out of scope."),
    _c(3, "session_management", "Session Management", 1, "critical", PASSIVE, "A07",
       "How a session is issued, carried and ended: cookie attributes, fixation, "
       "lifetime, and invalidation on logout."),
    _c(4, "injection", "Injection", 1, "critical", ACTIVE, "A03",
       "User input reaching an interpreter: SQL, command, template, and reflected or "
       "stored script. Passive observation can suggest it; confirmation needs payloads."),
    _c(5, "security_misconfiguration", "Security Misconfiguration", 1, "critical", PASSIVE, "A05",
       "Defaults, headers and surfaces left in an unsafe state. The most "
       "passively-assessable category, and the best covered here."),
    _c(6, "cryptographic_failures", "Cryptographic Failures", 1, "high", PASSIVE, "A02",
       "Secrets in transit or at rest without adequate protection: cleartext transport, "
       "missing transport security, weak or absent enforcement."),
    _c(7, "information_disclosure", "Information Disclosure", 1, "high", PASSIVE, "A01",
       "Content the application reveals without needing to: stack traces, internal "
       "paths, versions, comments, timestamps."),
    _c(8, "file_upload", "File Upload", 1, "high", ACTIVE, "A04",
       "Accepting, storing and serving user files: type and size enforcement, storage "
       "location, and what happens when the file is retrieved."),
    _c(9, "api_security", "API Security", 1, "high", ACTIVE, "A04",
       "API-specific surface: method handling, object-level authorisation, mass "
       "assignment, verbose responses, and rate limiting."),
    _c(10, "business_logic", "Business Logic", 1, "high", MANUAL, None,
        "Flaws in what the application permits rather than how it is built: order of "
        "operations, quantity and price manipulation, workflow skipping. No scanner "
        "confirms these; the platform's job is to point a human at the surface."),
    _c(11, "ssrf", "Server-Side Request Forgery", 1, "high", ACTIVE, "A10",
        "Parameters that cause the server to fetch a URL the caller controls, reaching "
        "internal services the caller cannot."),
    _c(12, "client_side", "Client-Side", 1, "high", PASSIVE, "A03",
        "What executes in the browser: DOM sinks, client-side storage of sensitive "
        "values, third-party script inclusion, and the policies that constrain them."),
)

# Tier 2 — after the first demonstration.
TIER2: tuple[Category, ...] = (
    _c(20, "software_supply_chain", "Software Supply Chain", 2, "high", PASSIVE, "A06",
        "Known-vulnerable or unmaintained components, and the integrity of what the "
        "application loads from elsewhere."),
    _c(21, "infrastructure_configuration", "Infrastructure Configuration", 2, "medium", PASSIVE, "A05",
        "The platform underneath the application: exposed services, TLS configuration, "
        "server software posture."),
    _c(22, "denial_of_service", "Denial of Service", 2, "medium", ACTIVE, None,
        "Resource exhaustion and amplification. EXCLUDED from execution by project "
        "constraint: it is catalogued so it can be reported as out of scope, never run."),
    _c(23, "http_protocol", "HTTP Protocol", 2, "medium", ACTIVE, None,
        "Request smuggling, response splitting, header injection, and inconsistent "
        "parsing between hops."),
    _c(24, "error_handling", "Error Handling", 2, "medium", PASSIVE, "A05",
        "How failures are surfaced: unhandled exceptions, inconsistent status codes, "
        "and what an error reveals."),
    _c(25, "logging_monitoring", "Logging and Monitoring", 2, "medium", MANUAL, "A09",
        "Whether security-relevant events are recorded and detectable. Assessable only "
        "with access the platform does not have from outside."),
    _c(26, "identity_management", "Identity Management", 2, "medium", ACTIVE, "A07",
        "Registration, provisioning, role assignment and de-provisioning over an "
        "account's lifetime."),
    _c(27, "privacy", "Privacy", 2, "medium", MANUAL, None,
        "Collection, retention and exposure of personal data, including what leaves the "
        "application to third parties."),
)

ALL: tuple[Category, ...] = TIER1 + TIER2
BY_KEY: dict[str, Category] = {c.key: c for c in ALL}
TIER1_KEYS: tuple[str, ...] = tuple(c.key for c in TIER1)

# A detection that no catalogue entry covers. Deliberately NOT a category: it is
# the absence of one, and reports must not let it masquerade as coverage.
UNMAPPED = "unmapped_detection"


def is_category(key: str | None) -> bool:
    return key in BY_KEY


def tier1_gaps(detected: set[str]) -> tuple[str, ...]:
    """Tier-1 categories this build cannot assert anything about."""
    return tuple(k for k in TIER1_KEYS if k not in detected)
