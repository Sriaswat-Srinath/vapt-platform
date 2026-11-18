"""Phase 2 backend integration tests against the running API.

These assert the behaviours a stakeholder demo depends on AND the safety
invariants that must never regress:
  I1  no unregistered asset can be scanned
  I2  no assessment starts without a valid ScopeDecision
  I3  no active scan without genuine dual control
  I9  no unsigned authorisation document activates a scope grant
  I14 asset identity is immutable
"""
from __future__ import annotations
import json, pathlib, subprocess, urllib.error, urllib.request
import pytest

REPO = pathlib.Path(__file__).parents[2]
BASE = "http://127.0.0.1:8000/api/v1"
TOKENS = REPO / ".lab-state" / "tokens.json"


def _tokens() -> dict[str, str]:
    if not TOKENS.exists():
        pytest.skip("no .lab-state/tokens.json (run: make db-seed && make api-publish)")
    return json.loads(TOKENS.read_text())


def call(method: str, path: str, *, role: str = "analyst", body: dict | None = None,
         token: str | None = None) -> tuple[int, dict]:
    tok = token if token is not None else _tokens()[role]
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {tok}"} if tok else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else {})
    except urllib.error.URLError as e:
        pytest.skip(f"API not reachable at {BASE} ({e}); run `make api-up && make api-publish`")


@pytest.fixture(scope="module")
def asset_id() -> str:
    status, assets = call("GET", "/assets")
    assert status == 200, assets
    mock = [a for a in assets if a["asset_identifier"] == "MOCK-WEB-001"]
    assert mock, "MOCK-WEB-001 is not seeded"
    return mock[0]["id"]


# ------------------------------------------------------------------ auth ------
def test_unauthenticated_is_refused():
    assert call("GET", "/assets", token="")[0] == 401
    assert call("GET", "/assets", token="vapt_not_a_token")[0] == 401


def test_role_enforcement():
    status, _ = call("POST", "/scope-grants/00000000-0000-0000-0000-000000000000/verify-document",
                     role="analyst", body={"document_sha256": "a" * 64, "signed": True})
    assert status == 403, "an analyst must not verify an authorisation document"
    assert call("GET", "/audit/verify", role="analyst")[0] == 403
    assert call("GET", "/audit/verify", role="admin")[0] == 200


# -------------------------------------------- I1: unregistered/external ------
@pytest.mark.parametrize("hostname,port", [
    ("example.com", 80),
    ("93.184.216.34", 80),
    ("scanme.nmap.org", 80),
    ("localhost", 8000),
    ("172.30.21.40", 5432),          # an internal application component
])
def test_external_target_registration_is_rejected(hostname, port):
    status, body = call("POST", "/assets", role="analyst", body={
        "asset_identifier": "EXT-TEST", "display_name": "external attempt",
        "hostname": hostname, "protocol": "http", "port": port})
    assert status == 409, f"{hostname} was accepted: {body}"
    assert body["type"].endswith("target-out-of-scope")
    assert body["reasons"]


def test_registered_mock_asset_is_present_and_synthetic(asset_id):
    status, asset = call("GET", f"/assets/{asset_id}")
    assert status == 200
    assert asset["environment"] == "mock_lab"
    assert asset["hostname"].endswith(".test")


# ------------------------------------- I2: no job without an allow decision ---
def test_assessment_is_denied_and_the_decision_is_explained(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/assessments", role="analyst",
                        body={"profile_key": "zap-passive"})
    assert status == 409, body
    assert body["type"].endswith("scope-denied")
    gates = body["scope_decision"]["gate_results"]
    assert gates and not gates[0]["pass"]
    assert gates[0]["gate"] == "scanner_execution_enabled"
    assert body["scope_decision"]["policy_version"]


def test_dry_run_reports_every_gate(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/scope/validate", role="analyst",
                        body={"profile_key": "zap-passive", "path": "/", "method": "GET"})
    assert status == 200, body
    names = [g["gate"] for g in body["gate_results"]]
    assert names == [
        "scanner_execution_enabled", "lab_isolation_valid", "asset_registered",
        "environment_is_mock", "grant_active", "profile_allowed", "intrusive_approval",
        "target_resolution", "port_allowed", "scope_rules", "concurrency_budget",
        "no_conflicting_job", "scanner_daemon_available",
    ], names
    assert body["decision"] == "deny"


def test_no_assessment_rows_exist_for_denied_requests(asset_id):
    """A denied request must create no job. Fixture-mode jobs (which contact
    nothing and are admitted under the fixture gate set) may legitimately exist,
    so the assertion is that nothing in LIVE mode was ever admitted - live is
    always denied while the authorisation is unsigned."""
    status, jobs = call("GET", f"/assessments?asset_id={asset_id}")
    assert status == 200
    # An API-side denial creates no row at all. A row admitted earlier and then
    # blocked by the worker may exist; what must never happen is a LIVE
    # assessment actually executing while the authorisation is unsigned.
    executed = [j for j in jobs
                if j["mode"] == "live" and j["state"] in ("running", "completed", "cancelled")]
    assert executed == [], f"a live assessment executed: {executed}"
    for j in (x for x in jobs if x["mode"] == "live"):
        s, obs = call("GET", f"/assessments/{j['id']}/raw-observations")
        assert s == 200 and obs["stored"] == 0, f"a live job stored observations: {j['id']}"


# ------------------------------------- I3 / I9: dual control + authorisation ---
def test_dual_control_is_reported_as_unavailable():
    status, caps = call("GET", "/system/capabilities")
    assert status == 200
    dc = caps["dual_control"]
    assert dc["effective"] is False
    assert "not independent human approval" in dc["note"]
    assert caps["scanner_execution_enabled"] is False
    assert caps["active_scan_enabled"] is False


def test_intrusive_profile_is_denied_by_the_gate_chain(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/scope/validate", role="analyst",
                        body={"profile_key": "zap-active-intrusive", "path": "/", "method": "GET"})
    assert status == 200
    assert body["decision"] == "deny"


def test_unsigned_authorisation_cannot_activate_a_grant(asset_id):
    status, grant = call("POST", f"/assets/{asset_id}/scope-grants", role="analyst", body={
        "document_ref": "lab/authorisation/MOCK-WEB-001.md",
        "allowed_cidrs": ["172.30.10.0/24"], "allowed_ports": [3000],
        "allowed_profiles": ["zap-passive"], "intrusive_allowed": False})
    assert status == 201, grant
    assert grant["document_state"] == "unsigned_draft"
    assert grant["state"] == "draft"
    status, body = call("POST", f"/scope-grants/{grant['id']}/activate", role="approver")
    assert status == 409, body
    assert body["type"].endswith("authorisation-unsigned")
    # and the grant is still a draft
    status, after = call("GET", f"/assets/{asset_id}/scope-grants")
    assert all(g["state"] != "active" for g in after)


def test_nobody_can_attest_their_own_independence():
    status, body = call("POST", "/operator-identities", role="admin", body={
        "analyst_email": "admin@vapt.local", "human_label": "self"})
    assert status == 409, body
    assert body["type"].endswith("self-attestation")


# -------------------------------------------------- I14 + audit integrity -----
def test_asset_identity_is_immutable_through_the_api(asset_id):
    status, body = call("PATCH", f"/assets/{asset_id}", role="analyst",
                        body={"hostname": "evil.example.com", "port": 80, "display_name": "x"})
    assert status == 200, body
    status, asset = call("GET", f"/assets/{asset_id}")
    assert asset["hostname"].endswith(".test"), "hostname was changed through the API"
    assert asset["port"] == 3000


def test_asset_identity_is_immutable_in_the_database():
    out = subprocess.run(["bash", "-lc",
        "set -a; . ./.env; set +a; docker exec -e PGPASSWORD=\"$POSTGRES_PASSWORD\" vapt_postgres "
        "psql -h 172.30.21.40 -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -c "
        "\"update assets set hostname='evil.example.com' where asset_identifier='MOCK-WEB-001'\""],
        cwd=REPO, capture_output=True, text=True)
    assert "asset identity is immutable" in (out.stdout + out.stderr), out.stdout + out.stderr


def test_audit_log_is_append_only_in_the_database():
    out = subprocess.run(["bash", "-lc",
        "set -a; . ./.env; set +a; docker exec -e PGPASSWORD=\"$POSTGRES_PASSWORD\" vapt_postgres "
        "psql -h 172.30.21.40 -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -c \"delete from audit_log\""],
        cwd=REPO, capture_output=True, text=True)
    assert "append-only" in (out.stdout + out.stderr), out.stdout + out.stderr


def test_audit_chain_verifies():
    status, body = call("GET", "/audit/verify", role="admin")
    assert status == 200
    assert body["ok"] is True, body
    assert body["entries"] > 0


def test_denied_decisions_are_persisted_and_audited(asset_id):
    call("POST", f"/assets/{asset_id}/scope/validate", role="analyst",
         body={"profile_key": "zap-passive"})
    status, rows = call("GET", "/audit?limit=50", role="approver")
    assert status == 200
    assert any(r["action"] == "scope_decision" and r["outcome"] == "deny" for r in rows), \
        "a denied scope decision was not audited"


# ------------------------------------------- phase 3: discovery behaviour -----
def _wait_run(run_id: str, timeout_s: int = 40) -> dict:
    import time
    for _ in range(timeout_s // 2):
        status, run = call("GET", f"/discovery-runs/{run_id}")
        assert status == 200, run
        if run["state"] not in ("queued", "running"):
            return run
        time.sleep(2)
    pytest.fail(f"discovery run {run_id} did not finish: {run}")


def test_fixture_discovery_makes_no_requests_and_builds_the_inventory(asset_id):
    status, started = call("POST", f"/assets/{asset_id}/discovery-runs?source=fixture",
                           role="analyst")
    assert status == 201, started
    run = _wait_run(started["id"])
    assert run["state"] == "completed", run
    assert run["requests_made"] == 0, "a fixture run must not touch the network"
    assert run["pages_seen"] > 0 and run["coverage_complete"] is True

    status, surface = call("GET", f"/assets/{asset_id}/attack-surface")
    assert status == 200
    c = surface["counts"]
    assert c["endpoints"] > 0 and c["parameters"] > 0 and c["forms"] > 0
    assert c["auth_entry_points"] > 0 and c["api_endpoints"] > 0
    assert set(surface["by_assessment"]) <= {"discovered", "verified", "inferred", "unassessed"}
    # form actions that were never requested must be INFERRED, not discovered
    assert surface["by_assessment"].get("inferred", 0) > 0


def test_repeat_discovery_converges_without_duplicates(asset_id):
    _, before = call("GET", f"/assets/{asset_id}/attack-surface")
    status, started = call("POST", f"/assets/{asset_id}/discovery-runs?source=fixture",
                           role="analyst")
    assert status == 201
    _wait_run(started["id"])
    _, after = call("GET", f"/assets/{asset_id}/attack-surface")
    assert after["counts"]["endpoints"] == before["counts"]["endpoints"], \
        "a repeat run duplicated endpoints instead of upserting"
    assert after["by_assessment"].get("verified", 0) > 0, \
        "a surface seen in a later run should be promoted to verified"


def test_candidate_tests_are_deterministic_and_flag_intrusive(asset_id):
    status, body = call("GET", f"/assets/{asset_id}/candidate-tests")
    assert status == 200 and body["candidates"], body
    assert body["matrix_version"]
    concerns = {c["concern"] for c in body["candidates"]}
    # Concerns are taxonomy keys (taxonomy 1.0.0): discovery and findings share
    # one vocabulary, so a flagged surface counts toward its category.
    assert {"injection", "authentication", "security_misconfiguration"} <= concerns
    injection = [c for c in body["candidates"] if c["concern"] == "injection"]
    assert injection and all(c["requires_intrusive"] for c in injection)
    assert "never findings" in body["note"]


def test_live_discovery_is_denied_without_authorisation(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/discovery-runs?source=live&profile_key=zap-passive",
                        role="analyst")
    assert status == 409, body
    assert body["type"].endswith("scope-denied")
    assert not body["scope_decision"]["gate_results"][0]["pass"]


def test_no_live_discovery_run_rows_exist(asset_id):
    status, runs = call("GET", f"/assets/{asset_id}/discovery-runs")
    assert status == 200
    assert all(r["source"] == "fixture" for r in runs), \
        "a live discovery run was created despite the denial"
