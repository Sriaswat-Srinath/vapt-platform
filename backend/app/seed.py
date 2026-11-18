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
