"""Idempotent development seed: accounts, tokens, scan profiles, MOCK-WEB-001.

Creates NO scope grant and signs NO authorisation document: scanner execution
stays denied. Run: `python -m app.seed`.
"""
from __future__ import annotations
import json
import sys
from typing import Any
from sqlalchemy import select
from . import audit, models, security, taxonomy
from .catalogue import CATALOGUE
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



# The lab's registered assets. Each has its OWN authorisation document: signing
# one grants nothing for the other, which is the behaviour a multi-application
# platform has to get right from the start rather than retrofit.
LAB_ASSETS: list[dict[str, Any]] = [
    dict(asset_identifier="MOCK-WEB-001",
         display_name="OWASP Juice Shop (local synthetic lab)",
         hostname="shop.brakes-vapt.test", port=3000,
         notes=("Deliberately vulnerable synthetic training application. Disposable. "
                "Contains no real data. Reachable only inside vapt_lab."),
         rules=[("include", "/", ["GET", "HEAD", "POST"], "Registered mock target surface"),
                ("exclude", "/rest/user/logout", [], "Session-destroying endpoint"),
                ("exclude", "/api/Users", [], "User mutation endpoints are out of scope"),
                ("exclude", "/rest/user/reset-password", [], "Credential-state mutation"),
                ("exclude", "/ftp", [], "Static file retrieval loop; no assessment value")]),
    dict(asset_identifier="MOCK-WEB-002",
         display_name="Supplier Portal (local synthetic lab)",
         hostname="portal.brakes-vapt.test", port=8080,
         notes=("Static synthetic mock portal — three files served by nginx, configured the way "
                "a hastily-deployed internal portal often is. No application behind it, no real "
                "supplier, no real data. Reachable only inside vapt_lab."),
         rules=[("include", "/", ["GET", "HEAD", "POST"], "Registered mock target surface"),
                ("exclude", "/signin", [], "Credential submission endpoint"),
                ("exclude", "/redirect", [], "Open-redirect surface; flagged, not exercised")]),
]


def _seed_assets(s) -> None:
    """Register each lab asset once, with its scope rules. Idempotent."""
    for spec in LAB_ASSETS:
        row = s.execute(select(models.Asset).where(
            models.Asset.asset_identifier == spec["asset_identifier"])).scalar_one_or_none()
        if row is not None:
            continue
        row = models.Asset(
            asset_identifier=spec["asset_identifier"], display_name=spec["display_name"],
            hostname=spec["hostname"], protocol="http", port=spec["port"], base_path="/",
            environment="mock_lab", criticality=1, state="active", notes=spec["notes"])
        s.add(row)
        s.flush()
        audit.record(s, action="asset_seeded", actor_kind="system", actor_id="seed",
                     outcome="ok", subject_type="asset", subject_id=str(row.id),
                     detail={"asset_identifier": spec["asset_identifier"]})
        for kind, path, methods, reason in spec["rules"]:
            s.add(models.ScopeRule(asset_id=row.id, kind=kind, host_pattern=row.hostname,
                                   port=row.port, path_prefix=path,
                                   method_allowlist=methods, reason=reason))


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

        # The taxonomy is seeded FIRST and in full, including categories this
        # build cannot detect: a coverage query must be able to return zeroes.
        for cat in taxonomy.ALL:
            row = s.execute(select(models.VulnTaxonomy).where(
                models.VulnTaxonomy.key == cat.key)).scalar_one_or_none()
            values = dict(display_name=cat.display_name, tier=cat.tier, priority=cat.priority,
                          assertability=cat.assertability, owasp_2021=cat.owasp_2021,
                          description=cat.description, sort_index=cat.sort_index,
                          taxonomy_version=taxonomy.TAXONOMY_VERSION)
            if row is None:
                s.add(models.VulnTaxonomy(key=cat.key, **values))
            else:
                for k, v in values.items():
                    setattr(row, k, v)

        # A catalogue entry naming a category the taxonomy does not define is a
        # seed-time failure, not a silent orphan.
        unknown = sorted({c["category"] for c in CATALOGUE
                          if not taxonomy.is_category(c["category"])})
        if unknown:
            raise SystemExit(f"catalogue entries name unknown taxonomy categories: {unknown}")

        for spec in CATALOGUE:
            row = s.execute(select(models.VulnCatalogue).where(
                models.VulnCatalogue.key == spec["key"])).scalar_one_or_none()
            if row is None:
                s.add(models.VulnCatalogue(**spec))
            else:
                # Re-filing an existing entry under the taxonomy must take
                # effect (HSTS moved to cryptographic_failures in 1.1.0).
                row.category = spec["category"]
                row.catalogue_version = spec["catalogue_version"]

        for spec in PROFILES:
            if s.execute(select(models.ScanProfile).where(
                    models.ScanProfile.key == spec["key"])).scalar_one_or_none() is None:
                s.add(models.ScanProfile(**spec))

        _seed_assets(s)
        s.commit()
    finally:
        s.close()
    print(json.dumps({"tokens": issued,
                      "taxonomy": {"version": taxonomy.TAXONOMY_VERSION,
                                   "categories": len(taxonomy.ALL),
                                   "tier1": len(taxonomy.TIER1)},
                      "catalogue_entries": len(CATALOGUE),
                      "assets": [a["asset_identifier"] for a in LAB_ASSETS],
                      "note": "No ScopeGrant created and no authorisation document signed for "
                              "ANY asset: scanner execution remains denied. Authorisation is "
                              "per asset."}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
