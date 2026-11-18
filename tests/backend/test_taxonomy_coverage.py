"""Taxonomy as first-class data, and this build's coverage of it.

What these tests defend: a category must not be able to disappear. The failure
mode that matters is not a wrong count — it is a Tier-1 category silently
absent from the table, so a reader concludes "nothing found" where the truth is
"never looked".
"""
from __future__ import annotations
import os, pathlib, sys
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("REDACTION_HMAC_KEY", "0" * 64)
from app import coverage as cv                                      # noqa: E402
from app import taxonomy as tax                                     # noqa: E402
from app.catalogue import CATALOGUE                                 # noqa: E402
from app.discovery import classify                                  # noqa: E402
from app.validation import engine as ve                             # noqa: E402

from test_backend_core import call, asset_id                        # noqa: E402,F401

OWNER_TIER1 = [
    "broken_access_control", "authentication", "session_management", "injection",
    "security_misconfiguration", "cryptographic_failures", "information_disclosure",
    "file_upload", "api_security", "business_logic", "ssrf", "client_side",
]
OWNER_TIER2 = [
    "software_supply_chain", "infrastructure_configuration", "denial_of_service",
    "http_protocol", "error_handling", "logging_monitoring", "identity_management",
    "privacy",
]


# ------------------------------------------------------------- the table ------
def test_tier1_is_exactly_the_twelve_categories_the_owner_specified():
    assert [c.key for c in tax.TIER1] == OWNER_TIER1


def test_tier2_is_exactly_the_eight_categories_the_owner_specified():
    assert [c.key for c in tax.TIER2] == OWNER_TIER2


def test_priorities_match_the_specification():
    critical = {"broken_access_control", "authentication", "session_management",
                "injection", "security_misconfiguration"}
    for c in tax.TIER1:
        expected = "critical" if c.key in critical else "high"
        assert c.priority == expected, f"{c.key} should be {expected}"


def test_every_category_declares_how_it_could_ever_be_confirmed():
    for c in tax.ALL:
        assert c.assertability in (tax.PASSIVE, tax.ACTIVE, tax.MANUAL), c.key
        assert c.description.strip(), c.key


# --------------------------------------------------------- the catalogue ------
def test_every_catalogue_entry_names_a_real_category():
    orphans = sorted({c["key"] for c in CATALOGUE if not tax.is_category(c["category"])})
    assert not orphans, f"catalogue entries with no taxonomy category: {orphans}"


def test_catalogue_covers_every_tier1_category_that_a_scanner_could_report():
    """Business logic is the one honest exception: no scanner confirms it."""
    covered = {c["category"] for c in CATALOGUE}
    missing = [k for k in tax.TIER1_KEYS if k not in covered]
    assert missing == ["business_logic"], missing


def test_catalogue_keys_are_unique():
    keys = [c["key"] for c in CATALOGUE]
    assert len(keys) == len(set(keys))


# ------------------------------------------------------- the discovery matrix --
def _endpoint(**over):
    base = dict(path="/", method="GET", is_api=False, api_style=None, auth_entry_kind="none",
                parameter_names=(), has_login_form=False, has_password_field=False,
                has_file_input=False, missing_security_headers=())
    base.update(over)
    return classify.candidates_for_endpoint(**base)


def test_every_emitted_concern_is_a_taxonomy_key():
    """Discovery and findings must speak ONE vocabulary, or a flagged surface can
    never be counted against the category it belongs to."""
    surfaces = [
        _endpoint(auth_entry_kind="login_form", has_password_field=True,
                  is_cleartext_transport=True),
        _endpoint(path="/rest/products/search", is_api=True, api_style="rest",
                  parameter_names=("q", "productId", "quantity", "imageUrl", "role")),
        _endpoint(has_file_input=True),
        _endpoint(missing_security_headers=("content-security-policy",)),
        _endpoint(set_cookie_attributes=("present",)),
        _endpoint(path="/admin/users"),
    ]
    for cands in surfaces:
        for c in cands:
            assert tax.is_category(c.concern), f"{c.concern} is not a taxonomy key"
            assert tax.BY_KEY[c.concern].tier == 1, f"{c.concern} is not Tier 1"


def test_the_matrix_can_emit_all_twelve_tier1_concerns():
    emitted: set[str] = set()
    for cands in (
        _endpoint(auth_entry_kind="login_form", has_password_field=True,
                  is_cleartext_transport=True),
        _endpoint(set_cookie_attributes=("present",)),
        _endpoint(path="/rest/products/search", is_api=True, api_style="rest",
                  parameter_names=("q", "productId", "quantity", "imageUrl")),
        _endpoint(has_file_input=True),
        _endpoint(missing_security_headers=("content-security-policy",)),
    ):
        emitted |= {c.concern for c in cands}
    missing = [k for k in tax.TIER1_KEYS if k not in emitted]
    assert not missing, f"the matrix cannot flag surface for: {missing}"


def test_intrusiveness_follows_the_category_not_the_caller():
    """An `active` category must never be proposed under a passive profile."""
    for cands in (
        _endpoint(path="/rest/x", is_api=True, api_style="rest",
                  parameter_names=("id", "url", "price")),
        _endpoint(has_file_input=True),
        _endpoint(missing_security_headers=("x-frame-options",)),
    ):
        for c in cands:
            cat = tax.BY_KEY[c.concern]
            if cat.assertability == tax.ACTIVE:
                assert c.requires_intrusive and c.suggested_profile_key == classify.ACTIVE_PROFILE
            elif cat.assertability == tax.PASSIVE:
                assert not c.requires_intrusive
                assert c.suggested_profile_key == classify.PASSIVE_PROFILE
            else:
                assert c.suggested_profile_key is None, \
                    "a manual category must not suggest that a scanner confirms it"


def test_parameter_names_tokenise_across_naming_conventions():
    for name in ("imageUrl", "image_url", "image-url", "BasketItem.imageUrl"):
        assert "url" in classify.tokens(name), name


def test_ssrf_is_flagged_only_on_url_shaped_names():
    assert any(c.concern == "ssrf" for c in _endpoint(parameter_names=("redirectUrl",)))
    assert not any(c.concern == "ssrf" for c in _endpoint(parameter_names=("username",)))


def test_business_logic_is_flagged_for_humans_and_never_automated():
    cands = [c for c in _endpoint(parameter_names=("quantity",)) if c.concern == "business_logic"]
    assert cands, "a commercial quantity parameter should be flagged"
    assert cands[0].suggested_profile_key is None
    assert "MANUAL" in cands[0].rationale


# ------------------------------------------------- the session-management pack --
def _cookie(**over):
    base = dict(evidence_class="cookie_attribute", coverage_complete=True,
                has_response_evidence=True, set_cookie_count=1,
                cookie_attribute_claimed_missing="HttpOnly")
    base.update(over)
    return ve.classify(ve.ValidationInputs(**base))


def test_cookie_rule_confirms_a_genuinely_missing_attribute():
    assert _cookie().state == ve.CONFIRMED


def test_cookie_rule_contradicts_the_scanner_when_the_attribute_is_present():
    assert _cookie(cookie_attributes_present=("HttpOnly",)).state == ve.FALSE_POSITIVE


def test_cookie_rule_refuses_a_claim_about_a_response_that_sets_no_cookie():
    assert _cookie(set_cookie_count=0).state == ve.FALSE_POSITIVE


def test_secure_is_not_applicable_over_cleartext_transport():
    out = _cookie(cookie_attribute_claimed_missing="Secure", transport_is_cleartext=True)
    assert out.state == ve.NOT_APPLICABLE
    assert "transport itself is the finding" in out.reason


def test_a_cookie_value_cannot_masquerade_as_an_attribute():
    """The first segment of Set-Cookie is NAME=VALUE and must not be parsed as
    an attribute: otherwise a cookie whose value contains "HttpOnly" would be
    read as carrying the flag, turning a real finding into a false positive."""
    from app.discovery import extractors
    assert extractors.cookie_attributes("token=HttpOnly; Path=/") == ()
    assert extractors.cookie_attributes("token=abc; Path=/; HttpOnly") == ("HttpOnly",)
    assert extractors.cookie_attributes("token=SameSite=Lax") == ()
    assert extractors.cookie_attributes(
        "s=1; HttpOnly; Secure; SameSite=Lax") == ("HttpOnly", "Secure", "SameSite")
    assert extractors.cookie_attributes(None) == ()


# ------------------------------------------------------------ the coverage ------
def _compute(**over):
    base = dict(candidate_counts={}, finding_counts={}, scanner_execution_enabled=False,
                active_scan_enabled=False, dual_control_effective=False)
    base.update(over)
    return cv.compute(**base)


def test_coverage_returns_every_category_including_the_zeroes():
    rows = _compute()
    assert [r.key for r in rows] == [c.key for c in tax.ALL]
    assert all(r.findings_total == 0 for r in rows)


def test_a_category_with_no_catalogue_entry_is_reported_as_no_capability():
    row = next(r for r in _compute() if r.key == "business_logic")
    assert row.detection == cv.NONE
    assert "says nothing about the target" in row.note


def test_passive_categories_with_rule_packs_report_as_detecting():
    for key in ("security_misconfiguration", "session_management", "information_disclosure"):
        assert next(r for r in _compute() if r.key == key).detection == cv.DETECTS, key


def test_active_categories_record_what_blocks_them():
    row = next(r for r in _compute() if r.key == "ssrf")
    assert "active scanning is disabled" in row.blocked_by
    assert "intrusive testing needs two independent approvals" in row.blocked_by


def test_summary_names_the_categories_this_build_cannot_report():
    s = cv.summary(_compute())
    assert s["tier1_total"] == 12
    assert "business_logic" in s["categories_this_build_cannot_report"]
    assert "not evidence of their absence" in s["note"]


# ------------------------------------------------------------- over the API ------
def test_taxonomy_endpoint_serves_all_twenty_categories():
    status, body = call("GET", "/taxonomy")
    assert status == 200, body
    assert [c["key"] for c in body] == [c.key for c in tax.ALL]
    assert {c["tier"] for c in body} == {1, 2}


def test_coverage_endpoint_reports_tier1_zeroes_for_the_registered_asset(asset_id):
    status, body = call("GET", f"/assets/{asset_id}/coverage")
    assert status == 200, body
    tier1 = [c for c in body["categories"] if c["tier"] == 1]
    assert len(tier1) == 12
    silent = [c for c in tier1 if c["detection"] in (cv.NONE, cv.CATALOGUED)]
    assert all(c["findings_total"] == 0 for c in silent), \
        "a category with no detection capability cannot have findings"
    assert body["summary"]["tier1_total"] == 12


def test_coverage_counts_uncategorised_detections_rather_than_hiding_them(asset_id):
    _, body = call("GET", f"/assets/{asset_id}/coverage")
    assert "uncategorised_findings" in body["summary"]
    assert body["summary"]["uncategorised_findings"] >= 0


@pytest.mark.parametrize("key", OWNER_TIER1)
def test_each_tier1_category_is_individually_reachable_over_the_api(asset_id, key):
    _, body = call("GET", f"/assets/{asset_id}/coverage")
    row = next((c for c in body["categories"] if c["key"] == key), None)
    assert row is not None, f"{key} is missing from the coverage response"
    assert row["priority"] in ("critical", "high")
    assert row["detection"] in (cv.NONE, cv.CATALOGUED, cv.SURFACE_ONLY, cv.PARTIAL, cv.DETECTS)


# ------------------------------------------------------------ in the report ------
def test_report_carries_a_coverage_section_naming_the_gaps(asset_id):
    status, report = call("POST", f"/assets/{asset_id}/reports?include_states=confirmed")
    assert status == 201, report
    _, detail = call("GET", f"/reports/{report['id']}")
    section = next((s for s in detail["sections"] if s["key"] == "coverage"), None)
    assert section is not None, "the report has no coverage section"
    assert len(section["data"]["categories"]) == len(tax.ALL)
    limitations = next(s for s in detail["sections"] if s["key"] == "limitations")["data"]["items"]
    joined = " ".join(limitations)
    assert "Tier-1 vulnerability categories were NOT assessable" in joined
    assert "not evidence of their absence" in joined
