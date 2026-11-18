"""Idempotent development seed: accounts, tokens, scan profiles, MOCK-WEB-001.

Creates NO scope grant and signs NO authorisation document: scanner execution
stays denied. Run: `python -m app.seed`.
"""
from __future__ import annotations
import json
import sys
from sqlalchemy import select
from . import audit, models, security
from .db import session_factory


PROFILES = [
    dict(key="zap-passive", display_name="ZAP passive (baseline, non-intrusive)",
         adapter_name="zap", is_intrusive=False, active_scan=False,
         max_requests_per_second=5, max_concurrent_requests=4, max_total_requests=5000,
         max_duration_seconds=1800, spider_max_depth=5, spider_max_children=20,
         excluded_path_patterns=["/rest/user/logout", "/api/Users", "/rest/user/reset-password", "/ftp"],
         method_denylist=["DELETE", "PUT", "PATCH"]),
    dict(key="zap-baseline-local", display_name="ZAP local baseline (spider + passive)",
         adapter_name="zap", is_intrusive=False, active_scan=False,
         max_requests_per_second=5, max_concurrent_requests=4, max_total_requests=5000,
         max_duration_seconds=1800, spider_max_depth=5, spider_max_children=20,
         excluded_path_patterns=["/rest/user/logout", "/api/Users", "/rest/user/reset-password", "/ftp"],
         method_denylist=["DELETE", "PUT", "PATCH"]),
    dict(key="mock-passive", display_name="Mock adapter passive (fixtures, no network)",
         adapter_name="mock", is_intrusive=False, active_scan=False,
         max_requests_per_second=5, max_concurrent_requests=4, max_total_requests=500,
         max_duration_seconds=300, spider_max_depth=3, spider_max_children=10,
         excluded_path_patterns=[], method_denylist=["DELETE", "PUT", "PATCH"]),
    # Present but unusable without genuine dual control (gate 7).
    dict(key="zap-active-intrusive", display_name="ZAP active (INTRUSIVE — requires dual control)",
         adapter_name="zap", is_intrusive=True, active_scan=True,
         max_requests_per_second=3, max_concurrent_requests=2, max_total_requests=3000,
         max_duration_seconds=1800, spider_max_depth=5, spider_max_children=20,
         excluded_path_patterns=["/rest/user/logout", "/api/Users", "/rest/user/reset-password"],
         method_denylist=["DELETE", "PUT", "PATCH"]),
]

# Curated vulnerability classes. Human-maintained; the ONLY default source of
# CVSS. Vectors and scores are the published CVSS v3.1 values for these classes.
CATALOGUE = [
    dict(key="missing-security-header-csp", title="Content-Security-Policy header not set",
         category="security_misconfiguration", cwe_ids=["CWE-693"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
         cvss_base=5.0,
         remediation_md=("Set a `Content-Security-Policy` response header on HTML responses. "
                         "Start with a report-only policy, review violations, then enforce."),
         references={"owasp": "https://owasp.org/www-project-secure-headers/"},
         catalogue_version="1.0.0"),
    dict(key="missing-security-header-frame-options",
         title="Anti-clickjacking header missing", category="security_misconfiguration",
         cwe_ids=["CWE-1021"], default_severity="medium", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", cvss_base=3.1,
         remediation_md=("Send `Content-Security-Policy: frame-ancestors 'none'` (or "
                         "`X-Frame-Options: DENY`) on HTML responses that must not be framed."),
         references={}, catalogue_version="1.0.0"),
    dict(key="missing-security-header-content-type-options",
         title="X-Content-Type-Options header missing", category="security_misconfiguration",
         cwe_ids=["CWE-693"], default_severity="low", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_base=3.1,
         remediation_md="Send `X-Content-Type-Options: nosniff` on all responses.",
         references={}, catalogue_version="1.0.0"),
    dict(key="missing-security-header-hsts",
         title="Strict-Transport-Security header missing", category="security_misconfiguration",
         cwe_ids=["CWE-319"], default_severity="medium", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", cvss_base=4.8,
         remediation_md=("Send `Strict-Transport-Security` over HTTPS. Not applicable to a "
                         "plain-HTTP lab target, which is why validation may mark it "
                         "not applicable."),
         references={}, catalogue_version="1.0.0"),
    dict(key="missing-security-header-permissions-policy",
         title="Permissions-Policy header missing", category="security_misconfiguration",
         cwe_ids=["CWE-693"], default_severity="low", cvss_version=None, cvss_vector=None,
         cvss_base=None,
         remediation_md="Send a `Permissions-Policy` header disabling unused browser features.",
         references={}, catalogue_version="1.0.0"),
    dict(key="cache-control-directives", title="Cache-control directives need review",
         category="security_misconfiguration", cwe_ids=["CWE-525"],
         default_severity="informational", cvss_version=None, cvss_vector=None, cvss_base=None,
         remediation_md=("Send `Cache-Control: no-store` on responses carrying sensitive data, "
                         "and review `public` on authenticated responses."),
         references={}, catalogue_version="1.0.0"),
    dict(key="timestamp-disclosure", title="Timestamp disclosure",
         category="information_disclosure", cwe_ids=["CWE-200"], default_severity="low",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=3.7,
         remediation_md=("Confirm the timestamp is not sensitive. Avoid returning internal "
                         "clock values where they reveal deployment detail."),
         references={}, catalogue_version="1.0.0"),
    dict(key="information-disclosure-debug-errors", title="Debug error messages disclosed",
         category="information_disclosure", cwe_ids=["CWE-209"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         cvss_base=5.3,
         remediation_md="Return generic error pages; log detail server-side only.",
         references={}, catalogue_version="1.0.0"),
    dict(key="information-disclosure-comments", title="Information disclosed in comments",
         category="information_disclosure", cwe_ids=["CWE-615"], default_severity="informational",
         cvss_version=None, cvss_vector=None, cvss_base=None,
         remediation_md="Strip developer comments from production responses.",
         references={}, catalogue_version="1.0.0"),
    dict(key="reflected-xss", title="Reflected cross-site scripting", category="injection",
         cwe_ids=["CWE-79"], default_severity="high", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_base=6.1,
         remediation_md=("Encode user input for the output context and apply a strict CSP. "
                         "Prefer framework auto-escaping over manual sanitisation."),
         references={}, catalogue_version="1.0.0"),
    dict(key="sql-injection", title="SQL injection", category="injection",
         cwe_ids=["CWE-89"], default_severity="critical", cvss_version="3.1",
         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_base=9.8,
         remediation_md="Use parameterised queries; never concatenate user input into SQL.",
         references={}, catalogue_version="1.0.0"),
    dict(key="missing-anti-csrf-token", title="Anti-CSRF token missing on a form",
         category="broken_access_control", cwe_ids=["CWE-352"], default_severity="medium",
         cvss_version="3.1", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
         cvss_base=4.3,
         remediation_md="Issue and verify a per-session anti-CSRF token on state-changing forms.",
         references={}, catalogue_version="1.0.0"),
]

ACCOUNTS = [
    ("admin@vapt.local", "Lab Administrator", "admin"),
    ("analyst@vapt.local", "Security Analyst", "analyst"),
    ("approver@vapt.local", "Assessment Approver", "approver"),
]


def main() -> int:
    s = session_factory()()
    issued: dict[str, str] = {}
    try:
        for email, name, role in ACCOUNTS:
            a = s.execute(select(models.Analyst).where(models.Analyst.email == email)).scalar_one_or_none()
            if a is None:
                a = models.Analyst(email=email, display_name=name, role=role)
                s.add(a)
                s.flush()
                audit.record(s, action="analyst_seeded", actor_kind="system", actor_id="seed",
                             outcome="ok", subject_type="analyst", subject_id=str(a.id),
                             detail={"email": email, "role": role})
            if not s.execute(select(models.ApiToken).where(
                    models.ApiToken.analyst_id == a.id,
                    models.ApiToken.revoked_at.is_(None))).scalars().all():
                _row, token = security.issue_token(s, a, label="seed")
                issued[email] = token

        for spec in CATALOGUE:
            if s.execute(select(models.VulnCatalogue).where(
                    models.VulnCatalogue.key == spec["key"])).scalar_one_or_none() is None:
                s.add(models.VulnCatalogue(**spec))

        for spec in PROFILES:
            if s.execute(select(models.ScanProfile).where(
                    models.ScanProfile.key == spec["key"])).scalar_one_or_none() is None:
                s.add(models.ScanProfile(**spec))

        asset = s.execute(select(models.Asset).where(
            models.Asset.asset_identifier == "MOCK-WEB-001")).scalar_one_or_none()
        if asset is None:
            asset = models.Asset(
                asset_identifier="MOCK-WEB-001",
                display_name="OWASP Juice Shop (local synthetic lab)",
                hostname="shop.brakes-vapt.test", protocol="http", port=3000, base_path="/",
                environment="mock_lab", criticality=1, state="active",
                notes=("Deliberately vulnerable synthetic training application. Disposable. "
                       "Contains no real data. Reachable only inside vapt_lab."))
            s.add(asset)
            s.flush()
            audit.record(s, action="asset_seeded", actor_kind="system", actor_id="seed",
                         outcome="ok", subject_type="asset", subject_id=str(asset.id),
                         detail={"asset_identifier": "MOCK-WEB-001"})
            rules = [
                ("include", "/", ["GET", "HEAD", "POST"], "Registered mock target surface"),
                ("exclude", "/rest/user/logout", [], "Session-destroying endpoint"),
                ("exclude", "/api/Users", [], "User mutation endpoints are out of scope"),
                ("exclude", "/rest/user/reset-password", [], "Credential-state mutation"),
                ("exclude", "/ftp", [], "Static file retrieval loop; no assessment value"),
            ]
            for kind, path, methods, reason in rules:
                s.add(models.ScopeRule(asset_id=asset.id, kind=kind,
                                       host_pattern=asset.hostname, port=asset.port,
                                       path_prefix=path, method_allowlist=methods, reason=reason))
        s.commit()
    finally:
        s.close()
    print(json.dumps({"tokens": issued,
                      "note": "No ScopeGrant created and no authorisation document signed: "
                              "scanner execution remains denied."}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
