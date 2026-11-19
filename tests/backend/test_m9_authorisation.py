"""M9 preparation: the authorisation document is verified, not just recorded.

The authorisation document states that "preflight gate 5 verifies the SHA-256
recorded in the grant against this file, so any edit after activation
invalidates the grant and blocks scanning until it is re-approved".

Before this, the digest was RECORDED and never checked: a signed document could
be edited after approval — widening scope, naming a different target — and
nothing would notice. These tests hold gate 5 to what the document promises.
"""
from __future__ import annotations
import datetime as dt
import hashlib, json, os, pathlib, subprocess, sys
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("REDACTION_HMAC_KEY", "0" * 64)
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-for-anything")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused")
from app.safety import scope_policy as sp                               # noqa: E402

from test_backend_core import call, asset_id                            # noqa: E402,F401

DOC = REPO / "lab" / "authorisation" / "MOCK-WEB-001.md"
GOOD = "a" * 64
OTHER = "b" * 64


def _grant(**over):
    base = dict(id="00000000-0000-0000-0000-000000000001",
                state="active", document_state="signed_verified",
                document_ref="lab/authorisation/MOCK-WEB-001.md", document_sha256=GOOD,
                allowed_cidrs=("172.30.10.0/24",), allowed_ports=(3000,),
                allowed_profiles=("zap-passive",), intrusive_allowed=False,
                revoked_at=None, valid_from=None, valid_until=None)
    base.update(over)
    return sp.GrantSnapshot(**base)


def _gate5(*, grant_over: dict | None = None, **over):
    now = dt.datetime.now(dt.timezone.utc)
    base = dict(now=now, subject_type="scan_job", mode=sp.MODE_LIVE,
                grant=_grant(**(grant_over or {})),
                attested_document_sha256=GOOD,
                attested_document_at=now - dt.timedelta(minutes=5),
                attestation_ttl_minutes=1440)
    base.update(over)
    return sp.GATES[4][2](sp.ScopeRequest(**base))


# ------------------------------------------------- what the document claims ---
def test_a_matching_fresh_attestation_passes():
    assert _gate5().passed is True


def test_an_edited_document_denies_even_though_the_grant_is_active_and_signed():
    """The whole point: approval was of a specific document, not of a filename."""
    out = _gate5(attested_document_sha256=OTHER)
    assert out.passed is False
    assert "CHANGED since it was approved" in out.reason
    assert "Re-verify and re-approve" in out.reason


def test_no_attestation_denies_rather_than_assuming_the_file_is_unchanged():
    out = _gate5(attested_document_sha256=None)
    assert out.passed is False
    assert "no current digest has been attested" in out.reason
    assert "make attest-authorisation" in out.reason


def test_a_grant_with_no_recorded_digest_denies():
    out = _gate5(grant_over={"document_sha256": None})
    assert out.passed is False
    assert "records no document digest" in out.reason


def test_a_stale_attestation_denies():
    now = dt.datetime.now(dt.timezone.utc)
    out = _gate5(attested_document_at=now - dt.timedelta(minutes=2000))
    assert out.passed is False
    assert "attestation is" in out.reason and "old" in out.reason


def test_the_unsigned_state_still_denies_before_any_digest_question():
    out = _gate5(grant_over={"document_state": "unsigned_draft"})
    assert out.passed is False
    assert "signed and verified" in out.reason


def test_the_policy_version_records_the_change():
    assert sp.POLICY_VERSION >= "1.2.0"


# ------------------------------------------------------ the document itself ---
def test_the_authorisation_document_is_still_an_unsigned_draft():
    """Nothing in this repository may sign it. If this fails, a human did —
    which is the intended way for it to change, and the point at which the rest
    of M9 becomes possible."""
    text = DOC.read_text()
    assert "STATUS: UNSIGNED DRAFT" in text
    block = text[text.index("## 7."):]
    rows = [r for r in block.splitlines() if r.startswith("|") and "---" not in r]
    # Columns are: role | name | title | date | signature. Only the role is
    # pre-filled; anything in the other four means a human signed it.
    filled = []
    for row in rows[1:]:
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if len(cells) >= 5 and any(cells[1:5]):
            filled.append(row)
    assert not filled, f"the signature table has been filled in: {filled}"


def test_the_document_promises_exactly_what_gate_5_now_enforces():
    import re
    # The document is a blockquote, so "> " survives a naive whitespace squash.
    text = re.sub(r"\s+", " ", DOC.read_text().replace("\n> ", " ").replace("\n>", " "))
    assert "Preflight gate 5 verifies the SHA-256 recorded in the grant against this file" in text
    assert "any edit after activation invalidates the grant and blocks scanning" in text


# --------------------------------------------------------- over the API -------
def test_attesting_the_real_document_reports_its_digest(asset_id):
    digest = hashlib.sha256(DOC.read_bytes()).hexdigest()
    status, body = call("POST", "/authorisation-documents/attest", role="admin",
                        body={"document_ref": "lab/authorisation/MOCK-WEB-001.md",
                              "document_sha256": digest, "byte_size": DOC.stat().st_size,
                              "note": "pytest"})
    assert status == 201, body
    assert body["document_sha256"] == digest


def test_an_attestation_that_differs_from_an_approved_grant_is_flagged():
    # A DISTINCT ref: a test must never write a bogus digest against the real
    # authorisation document, because gate 5 reads the latest attestation for
    # that document and the test would leave the platform denying for a reason
    # that has nothing to do with the document on disk.
    status, body = call("POST", "/authorisation-documents/attest", role="admin",
                        body={"document_ref": "tests/fixtures/not-a-real-document.md",
                              "document_sha256": OTHER, "note": "pytest tamper simulation"})
    assert status == 201, body
    # No grant has a recorded digest yet (none is signed), so nothing mismatches;
    # the contract is that the field exists and lists any grant that disagrees.
    assert "grants_with_a_different_digest" in body


def test_only_an_admin_may_attest():
    for role in ("analyst", "approver"):
        status, _ = call("POST", "/authorisation-documents/attest", role=role,
                         body={"document_ref": "x", "document_sha256": GOOD})
        assert status == 403, f"{role} must not be able to attest a document"


def test_attestations_are_listed_for_review():
    status, rows = call("GET", "/authorisation-documents/attestations"
                               "?document_ref=lab/authorisation/MOCK-WEB-001.md", role="analyst")
    assert status == 200, rows
    assert rows and rows[0]["document_sha256"]


def test_live_gate_5_still_denies_because_the_document_is_unsigned(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/scope/validate",
                        body={"profile_key": "zap-passive", "path": "/", "method": "GET"})
    assert status == 200, body
    gate5 = next(g for g in body["gate_results"] if g["gate"] == "grant_active")
    assert gate5["pass"] is False, "the lab document is unsigned; gate 5 must deny"


# ========================================== M9 readiness and ground truth =====
GROUND_TRUTH = REPO / "backend" / "fixtures" / "evaluation" / "m9_ground_truth.json"


def test_readiness_reports_blocked_and_never_changes_anything():
    """The readiness script must be read-only and must not claim readiness."""
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "m9_readiness.py")],
                         cwd=REPO, capture_output=True, text=True, timeout=180)
    if "tokens.json" in out.stderr:
        pytest.skip("platform not seeded")
    assert "M9 — first genuine passive assessment: readiness" in out.stdout
    assert out.returncode == 1, "readiness must report BLOCKED while the document is unsigned"
    assert "HUMAN: sign §7 by hand" in out.stdout
    src = (REPO / "scripts" / "m9_readiness.py").read_text()
    for forbidden in ("verify-document", "/activate", "SCANNER_EXECUTION_ENABLED=true"):
        assert f'"{forbidden}"' not in src and f"'{forbidden}'" not in src, \
            f"the readiness script must not be able to perform {forbidden}"


def test_ground_truth_is_limited_to_what_passive_observation_can_see():
    gt = json.loads(GROUND_TRUTH.read_text())
    assert gt["target"]["profile"] == "zap-passive"
    assert gt["not_expected_passively"], "the dataset must say what it cannot see"
    joined = " ".join(gt["not_expected_passively"]).lower()
    for active_only in ("sql injection", "xss", "idor", "business logic"):
        assert active_only in joined, f"{active_only} must be named as out of passive reach"


def test_every_expectation_carries_a_confidence_and_a_basis():
    for e in json.loads(GROUND_TRUTH.read_text())["expectations"]:
        assert e["confidence"] in ("high", "medium", "low"), e["id"]
        assert e["basis"].strip(), e["id"]


def test_the_comparison_warns_when_it_is_fed_fixture_output(asset_id):
    """Comparing fixture findings with real-world expectations is meaningless,
    and the tool must say so rather than print a flattering score."""
    status, jobs = call("GET", f"/assessments?asset_id={asset_id}")
    fixture_jobs = [j for j in jobs if j["mode"] == "fixture" and j["state"] == "completed"]
    if not fixture_jobs:
        pytest.skip("no completed fixture assessment")
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "m9_compare.py"),
                          "--job", fixture_jobs[0]["id"]],
                         cwd=REPO, capture_output=True, text=True, timeout=180)
    assert '"mode": "fixture"' in out.stdout, out.stdout + out.stderr
    assert "says nothing about live detection" in out.stdout


def test_no_live_assessment_has_ever_run(asset_id):
    """The honesty check for every report this platform produces."""
    status, jobs = call("GET", f"/assessments?asset_id={asset_id}")
    assert status == 200
    live = [j for j in jobs if j["mode"] == "live" and j["state"] == "completed"]
    assert not live, (
        "a live assessment exists — M9 has happened. Update this test, the reports' "
        "limitations and MILESTONE_STATE.json to say so.")
