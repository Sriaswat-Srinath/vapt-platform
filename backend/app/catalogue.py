"""The curated vulnerability catalogue.

Human-maintained and dependency-free, so normalisation, validation and the
coverage query can all import it without pulling in the ORM. Every entry's
`category` is a taxonomy key (app/taxonomy.py); the seed refuses to run if one
of them is not.

This is the ONLY default source of CVSS (ADR-0004). An LLM never writes here.
Vectors and scores are the published CVSS v3.1 values for these classes.
"""
from __future__ import annotations

CATALOGUE_VERSION = "1.1.0"

CATALOGUE = [
    dict(key="missing-security-header-csp", title="Content-Security-Policy header not set",
         category="security_misconfiguration", cwe_ids=["CWE-693"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cvss_base=5.0,
         remediation_md=("Set a `Content-Security-Policy` response header on HTML responses. "
                         "Start with a report-only policy, review violations, then enforce."),
         references={"owasp": "https://owasp.org/www-project-secure-headers/"},
         catalogue_version="1.1.0"),
    dict(key="missing-security-header-frame-options",
         title="Anti-clickjacking header missing", category="security_misconfiguration",
         cwe_ids=["CWE-1021"], default_severity="medium", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", cvss_base=3.1,
         remediation_md=("Send `Content-Security-Policy: frame-ancestors 'none'` (or "
                         "`X-Frame-Options: DENY`) on HTML responses that must not be framed."),
         references={}, catalogue_version="1.1.0"),
    dict(key="missing-security-header-content-type-options",
         title="X-Content-Type-Options header missing", category="security_misconfiguration",
         cwe_ids=["CWE-693"], default_severity="low", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_base=3.1,
         remediation_md="Send `X-Content-Type-Options: nosniff` on all responses.",
         references={}, catalogue_version="1.1.0"),
    dict(key="missing-security-header-hsts",
         title="Strict-Transport-Security header missing", category="cryptographic_failures",
         cwe_ids=["CWE-319"], default_severity="medium", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", cvss_base=4.8,
         remediation_md=("Send `Strict-Transport-Security` over HTTPS. Not applicable to a "
                         "plain-HTTP lab target, which is why validation may mark it "
                         "not applicable."),
         references={}, catalogue_version="1.1.0"),
    dict(key="missing-security-header-permissions-policy",
         title="Permissions-Policy header missing", category="security_misconfiguration",
         cwe_ids=["CWE-693"], default_severity="low", cvss_version=None, cvss_vector=None,
         cvss_base=None,
         remediation_md="Send a `Permissions-Policy` header disabling unused browser features.",
         references={}, catalogue_version="1.1.0"),
    dict(key="cache-control-directives", title="Cache-control directives need review",
         category="security_misconfiguration", cwe_ids=["CWE-525"],
         default_severity="informational", cvss_version=None, cvss_vector=None, cvss_base=None,
         remediation_md=("Send `Cache-Control: no-store` on responses carrying sensitive data, "
                         "and review `public` on authenticated responses."),
         references={}, catalogue_version="1.1.0"),
    dict(key="timestamp-disclosure", title="Timestamp disclosure",
         category="information_disclosure", cwe_ids=["CWE-200"], default_severity="low",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=3.7,
         remediation_md=("Confirm the timestamp is not sensitive. Avoid returning internal "
                         "clock values where they reveal deployment detail."),
         references={}, catalogue_version="1.1.0"),
    dict(key="information-disclosure-debug-errors", title="Debug error messages disclosed",
         category="information_disclosure", cwe_ids=["CWE-209"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=5.3,
         remediation_md="Return generic error pages; log detail server-side only.",
         references={}, catalogue_version="1.1.0"),
    dict(key="information-disclosure-comments", title="Information disclosed in comments",
         category="information_disclosure", cwe_ids=["CWE-615"], default_severity="informational",
         cvss_version=None, cvss_vector=None, cvss_base=None,
         remediation_md="Strip developer comments from production responses.",
         references={}, catalogue_version="1.1.0"),
    dict(key="reflected-xss", title="Reflected cross-site scripting", category="injection",
         cwe_ids=["CWE-79"], default_severity="high", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_base=6.1,
         remediation_md=("Encode user input for the output context and apply a strict CSP. "
                         "Prefer framework auto-escaping over manual sanitisation."),
         references={}, catalogue_version="1.1.0"),
    dict(key="sql-injection", title="SQL injection", category="injection",
         cwe_ids=["CWE-89"], default_severity="critical", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_base=9.8,
         remediation_md="Use parameterised queries; never concatenate user input into SQL.",
         references={}, catalogue_version="1.1.0"),
    # --- session management (passively confirmable from a stored response) ----
    dict(key="cookie-missing-httponly", title="Session cookie set without HttpOnly",
         category="session_management", cwe_ids=["CWE-1004"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
         cvss_base=3.1,
         remediation_md=("Set `HttpOnly` on session cookies so script cannot read them. A "
                         "cookie that client script must read should not also carry the "
                         "session."),
         references={"owasp": "https://owasp.org/www-community/HttpOnly"},
         catalogue_version="1.1.0"),
    dict(key="cookie-missing-secure", title="Cookie set without the Secure attribute",
         category="session_management", cwe_ids=["CWE-614"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=3.7,
         remediation_md=("Set `Secure` so the cookie is never sent over cleartext HTTP. On a "
                         "plain-HTTP lab target this is reported together with the transport "
                         "finding rather than in isolation."),
         references={}, catalogue_version="1.1.0"),
    dict(key="cookie-missing-samesite", title="Cookie set without SameSite",
         category="session_management", cwe_ids=["CWE-1275"], default_severity="low",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
         cvss_base=3.1,
         remediation_md=("Set `SameSite=Lax` (or `Strict` where no cross-site navigation needs "
                         "the cookie) to limit cross-site submission."),
         references={}, catalogue_version="1.1.0"),
    dict(key="session-id-in-url", title="Session identifier exposed in a URL",
         category="session_management", cwe_ids=["CWE-598"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
         cvss_base=4.3,
         remediation_md=("Carry session identifiers in cookies only. A URL is logged by proxies "
                         "and leaks through Referer."),
         references={}, catalogue_version="1.1.0"),
    # --- cryptographic failures -----------------------------------------------
    dict(key="cleartext-credential-transmission",
         title="Credentials submitted over cleartext HTTP",
         category="cryptographic_failures", cwe_ids=["CWE-319"], default_severity="high",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
         cvss_base=7.4,
         remediation_md=("Serve authentication over TLS and redirect HTTP to HTTPS before any "
                         "credential is submitted."),
         references={}, catalogue_version="1.1.0"),
    dict(key="sensitive-data-in-client-storage",
         title="Sensitive value written to client-side storage",
         category="cryptographic_failures", cwe_ids=["CWE-922"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
         cvss_base=3.1,
         remediation_md=("Keep tokens out of `localStorage`, which survives the tab and is "
                         "readable by any script on the origin."),
         references={}, catalogue_version="1.1.0"),
    # --- client-side ------------------------------------------------------------
    dict(key="dom-xss", title="DOM-based cross-site scripting",
         category="client_side", cwe_ids=["CWE-79"], default_severity="high",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cvss_base=6.1,
         remediation_md=("Avoid passing untrusted values into DOM sinks (`innerHTML`, "
                         "`document.write`, `eval`). Use textContent or a sanitiser."),
         references={}, catalogue_version="1.1.0"),
    dict(key="subresource-without-integrity",
         title="Third-party script loaded without Subresource Integrity",
         category="client_side", cwe_ids=["CWE-494"], default_severity="low",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
         cvss_base=4.2,
         remediation_md=("Add `integrity` and `crossorigin` to third-party script tags, or "
                         "self-host the dependency."),
         references={}, catalogue_version="1.1.0"),
    # --- information disclosure -------------------------------------------------
    dict(key="server-version-disclosure", title="Server or framework version disclosed",
         category="information_disclosure", cwe_ids=["CWE-200"], default_severity="low",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=5.3,
         remediation_md="Suppress `Server` and `X-Powered-By` version detail in responses.",
         references={}, catalogue_version="1.1.0"),
    # --- api security -------------------------------------------------------------
    dict(key="api-verbose-response", title="API response exposes fields the caller need not see",
         category="api_security", cwe_ids=["CWE-213"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=4.3,
         remediation_md=("Shape API responses to the caller's role rather than serialising the "
                         "whole record."),
         references={}, catalogue_version="1.1.0"),
    # --- broken access control ------------------------------------------------------
    dict(key="idor-object-reference", title="Insecure direct object reference",
         category="broken_access_control", cwe_ids=["CWE-639"], default_severity="high",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         cvss_base=6.5,
         remediation_md=("Check ownership on every object reference server-side; do not rely on "
                         "the identifier being unguessable."),
         references={}, catalogue_version="1.1.0"),
    # --- ssrf -----------------------------------------------------------------------
    dict(key="server-side-request-forgery", title="Server-side request forgery",
         category="ssrf", cwe_ids=["CWE-918"], default_severity="high",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
         cvss_base=8.5,
         remediation_md=("Allowlist the destinations the server may fetch, resolve and pin the "
                         "address, and refuse internal ranges."),
         references={}, catalogue_version="1.1.0"),
    # --- file upload -----------------------------------------------------------------
    dict(key="unrestricted-file-upload", title="Unrestricted file upload",
         category="file_upload", cwe_ids=["CWE-434"], default_severity="high",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
         cvss_base=8.8,
         remediation_md=("Enforce type and size server-side, store outside the web root, and "
                         "serve with a non-executable content type."),
         references={}, catalogue_version="1.1.0"),
    # --- authentication ----------------------------------------------------------------
    dict(key="user-enumeration", title="Account existence disclosed by response differences",
         category="authentication", cwe_ids=["CWE-204"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=5.3,
         remediation_md=("Return the same response and timing for known and unknown accounts on "
                         "login and password reset."),
         references={}, catalogue_version="1.1.0"),
    dict(key="missing-anti-csrf-token", title="Anti-CSRF token missing on a form",
         category="broken_access_control", cwe_ids=["CWE-352"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
         cvss_base=4.3,
         remediation_md="Issue and verify a per-session anti-CSRF token on state-changing forms.",
         references={}, catalogue_version="1.1.0"),
]
