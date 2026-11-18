"""ZAP plugin id -> catalogue key, severity and confidence. Versioned.

An unmapped plugin id is NEVER dropped: it produces a finding with a null
catalogue key and a conservative severity, and is surfaced separately as an
"unmapped detection" (docs/SCANNER_INTEGRATION.md §3).
"""
from __future__ import annotations

MAPPING_VERSION = "1.1.0"

# plugin id -> (catalogue key, evidence class)
#   evidence class drives which validation rule pack applies, and is part of the
#   fingerprint so a change of evidence class re-opens a finding.
PLUGIN_MAP: dict[str, tuple[str, str]] = {
    "10038": ("missing-security-header-csp", "missing_header"),
    "10020": ("missing-security-header-frame-options", "missing_header"),
    "10021": ("missing-security-header-content-type-options", "missing_header"),
    "10035": ("missing-security-header-hsts", "missing_header"),
    "10063": ("missing-security-header-permissions-policy", "missing_header"),
    "10015": ("cache-control-directives", "header_value"),
    "10096": ("timestamp-disclosure", "pattern_in_body"),
    "10027": ("information-disclosure-comments", "pattern_in_body"),
    "10023": ("information-disclosure-debug-errors", "pattern_in_body"),
    "40012": ("reflected-xss", "reflected_input"),
    "40018": ("sql-injection", "reflected_input"),
    "10202": ("missing-anti-csrf-token", "missing_form_token"),
    # --- session management (1.1.0) ---------------------------------------
    "10010": ("cookie-missing-httponly", "cookie_attribute"),
    "10011": ("cookie-missing-secure", "cookie_attribute"),
    "10054": ("cookie-missing-samesite", "cookie_attribute"),
    "00003": ("session-id-in-url", "pattern_in_body"),
    # --- cryptographic failures -------------------------------------------
    "10041": ("cleartext-credential-transmission", "pattern_in_body"),
    "10044": ("sensitive-data-in-client-storage", "pattern_in_body"),
    # --- client-side --------------------------------------------------------
    "40026": ("dom-xss", "reflected_input"),
    "90003": ("subresource-without-integrity", "pattern_in_body"),
    # --- information disclosure ---------------------------------------------
    "10036": ("server-version-disclosure", "header_value"),
}

# Which cookie attribute each cookie rule claims is missing. The attribute NAME
# is what the rule pack checks; the cookie value is never read.
COOKIE_ATTRIBUTE_CLAIM: dict[str, str] = {
    "10010": "HttpOnly",
    "10011": "Secure",
    "10054": "SameSite",
}


def cookie_attribute_claim(plugin_id: str | None) -> str | None:
    return COOKIE_ATTRIBUTE_CLAIM.get(str(plugin_id)) if plugin_id else None

ZAP_RISK_TO_SEVERITY = {
    "informational": "informational", "info": "informational",
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}
ZAP_CONFIDENCE = {
    "false positive": "low", "low": "low", "medium": "medium",
    "high": "high", "confirmed": "confirmed_by_tool",
}


def map_plugin(plugin_id: str | None) -> tuple[str | None, str]:
    """Returns (catalogue_key, evidence_class). Unmapped -> (None, 'unmapped')."""
    if not plugin_id:
        return None, "unmapped"
    entry = PLUGIN_MAP.get(str(plugin_id))
    if entry is None:
        return None, "unmapped"
    return entry


def map_severity(risk: str | None) -> str:
    return ZAP_RISK_TO_SEVERITY.get((risk or "").strip().lower(), "low")


def map_confidence(confidence: str | None) -> str:
    return ZAP_CONFIDENCE.get((confidence or "").strip().lower(), "low")
