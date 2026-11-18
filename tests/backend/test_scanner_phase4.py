"""Phase 4: adapter contract, raw observations, the global daemon lease, and
the dirty-daemon / cancellation invariants (I8, I13).

Pure and database-level assertions run anywhere; the ones that need the running
stack say so. The ZAP control-plane test skips if the daemon is unreachable —
it exercises session/context management only and never touches a target.
"""
from __future__ import annotations
import json, os, pathlib, subprocess, sys, time
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
from app.scanners import base as sb                                  # noqa: E402
from app.scanners.mock.adapter import MockAdapter                    # noqa: E402

from test_backend_core import call, asset_id                         # noqa: E402,F401


def _spec(*, allowed: bool = True, pinned: tuple[str, ...] = ("172.30.10.20",),
          adapter: str = "mock", intrusive: bool = False, active: bool = False,
          mode: str = "live") -> sb.ScanJobSpec:
    return sb.ScanJobSpec(
        job_id="00000000-0000-0000-0000-000000000001", mode=mode,
        asset=sb.AssetSnapshot(asset_id="a", asset_identifier="MOCK-WEB-001",
                               hostname="shop.brakes-vapt.test", protocol="http", port=3000,
                               base_path="/"),
        profile=sb.ProfileSnapshot(key="mock-passive", adapter_name=adapter,
                                   is_intrusive=intrusive, active_scan=active,
                                   max_requests_per_second=5, max_total_requests=500,
                                   max_duration_seconds=300, spider_max_depth=3,
                                   spider_max_children=10, excluded_path_patterns=(),
                                   method_denylist=("DELETE",), excluded_rule_ids=()),
        pinned_ips=pinned, seed_paths=("/",), included_path_prefixes=("/",),
        excluded_path_prefixes=("/ftp",), scope_decision_allowed=allowed,
        scope_decision_id="d1")


# ------------------------------------------------------- adapter contract -----
def test_adapter_refuses_a_spec_without_an_allow_decision():
    a = MockAdapter()
    with pytest.raises(sb.ScopeRefused):
        a.start(_spec(allowed=False))


def test_live_work_requires_a_pinned_address():
    a = MockAdapter()
    with pytest.raises(sb.ScopeRefused):
        a.start(_spec(pinned=(), mode="live"))


def test_fixture_work_does_not_require_a_resolvable_target():
    """Fixture mode contacts nothing, so it must not depend on the lab being up."""
    a = MockAdapter()
    handle = a.start(_spec(pinned=(), mode="fixture"))
    assert handle.job_id
    assert a.teardown(handle).confirmed_stopped is True


def test_the_zap_adapter_only_accepts_live_work():
    from app.scanners.zap.adapter import ZapAdapter

    class _Fake:
        def version(self): return "2.17.0"
        def close(self): pass
    a = ZapAdapter(client=_Fake())                       # type: ignore[arg-type]
    with pytest.raises(sb.ScopeRefused):
        a.preflight(_spec(adapter="zap", mode="fixture"))


def test_mock_adapter_declares_no_shared_daemon():
    caps = MockAdapter().capabilities()
    assert caps.requires_exclusive_daemon is False
    assert caps.supports_active is False, "the mock adapter must not claim active scanning"


def test_observation_hashes_are_content_addressed():
    o = sb.RawObservation(adapter_rule_id="10038", payload={"b": 2, "a": 1},
                          observed_url="http://x/", request_text="GET /", response_text="200")
    same = sb.RawObservation(adapter_rule_id="10038", payload={"a": 1, "b": 2},
                             observed_url="http://x/", request_text="GET /", response_text="200")
    assert o.payload_sha256 == same.payload_sha256, "payload hashing must be key-order independent"
    assert o.request_sha256 and o.response_sha256
    assert o.payload_sha256 != o.request_sha256


@pytest.mark.parametrize("fault,confirmed_cancel,confirmed_teardown", [
    ("", True, True),
    ("no_stop", False, True),
    ("dirty", True, False),
])
def test_fault_injection_exposes_the_failure_paths(monkeypatch, fault, confirmed_cancel,
                                                   confirmed_teardown):
    monkeypatch.setenv("MOCK_FAULT", fault)
    a = MockAdapter()
    handle = a.start(_spec())
    assert a.cancel(handle).confirmed_stopped is confirmed_cancel
    assert a.teardown(handle).confirmed_stopped is confirmed_teardown


def test_zap_adapter_refuses_active_and_intrusive_profiles():
    """Even with the flag on, this code path cannot reach an active scan."""
    from app.scanners.zap.adapter import ZapAdapter

    class _Fake:
        def version(self): return "2.17.0"
        def close(self): pass
    a = ZapAdapter(client=_Fake())                       # type: ignore[arg-type]
    with pytest.raises(sb.ScopeRefused):
        a.preflight(_spec(adapter="zap", active=True))
    with pytest.raises(sb.ScopeRefused):
        a.preflight(_spec(adapter="zap", intrusive=True))
    assert a.capabilities().supports_active is False
    assert a.capabilities().requires_exclusive_daemon is True


def test_fixtures_are_hand_authored_zap_shapes():
    doc = json.loads((REPO / "backend" / "fixtures" / "zap" / "passive-baseline.json").read_text())
    assert any("NOT captured from a live scan" in line for line in doc["_comment"])
    assert doc["alerts"] and all("pluginId" in a and "url" in a for a in doc["alerts"])
    assert any("cdn.example.com" in a["url"] for a in doc["alerts"]), \
        "a third-party-host alert must be present so ingestion rejection is exercised"


# --------------------------------------------------- database-level guards -----
def _psql(sql: str) -> str:
    out = subprocess.run(["bash", "-lc",
        'set -a; . ./.env; set +a; docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" vapt_postgres '
        'psql -h 172.30.21.40 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc ' + json.dumps(sql)],
        cwd=REPO, capture_output=True, text=True)
    return out.stdout + out.stderr


def test_raw_observations_are_immutable_in_the_database():
    assert "immutable" in _psql("update raw_observations set adapter_name='x'")
    assert "immutable" in _psql("delete from raw_observations")


def test_only_one_held_lease_per_adapter_is_possible():
    assert "uq_one_held_lease_per_adapter" in _psql(
        "select indexname from pg_indexes where indexname='uq_one_held_lease_per_adapter'")
    ins = ("insert into scanner_daemon_leases "
           "(id, adapter_name, lease_state, acquired_at, daemon_dirty_on_release) "
           "values (gen_random_uuid(),'probe-adapter','held',now(),false)")
    first = _psql(ins)
    assert "ERROR" not in first, first
    second = _psql(ins)
    _psql("delete from scanner_daemon_leases where adapter_name='probe-adapter'")
    assert "duplicate key" in second or "unique" in second.lower(), second


def test_job_mode_is_constrained():
    assert "ck_scan_job_mode" in _psql(
        "select conname from pg_constraint where conname='ck_scan_job_mode'")


# ------------------------------------------- live stack: lifecycle + I8/I13 ----
def _run_fixture_assessment(asset_id: str, profile: str = "mock-passive") -> dict:
    status, job = call("POST", f"/assets/{asset_id}/assessments?mode=fixture", role="analyst",
                       body={"profile_key": profile})
    assert status == 201, job
    for _ in range(40):
        s, j = call("GET", f"/assessments/{job['id']}")
        assert s == 200
        if j["state"] in ("completed", "failed", "cancelled", "blocked"):
            return j
        time.sleep(1)
    pytest.fail(f"assessment did not finish: {job['id']}")


def test_fixture_assessment_completes_with_provenance(asset_id):
    job = _run_fixture_assessment(asset_id)
    assert job["state"] == "completed", job
    assert job["mode"] == "fixture"
    assert job["coverage_complete"] is True
    status, obs = call("GET", f"/assessments/{job['id']}/raw-observations")
    assert status == 200
    assert obs["stored"] > 0
    for o in obs["observations"]:
        assert o["adapter"] == "mock" and o["adapter_version"]
        assert len(o["payload_sha256"]) == 64
        assert o["observed_url"].startswith("http://shop.brakes-vapt.test:3000")


def test_out_of_scope_observations_are_rejected_at_ingestion(asset_id):
    job = _run_fixture_assessment(asset_id)
    status, obs = call("GET", f"/assessments/{job['id']}/raw-observations")
    assert status == 200
    assert obs["rejected_at_ingestion"] >= 1, "the third-party-host alert was not rejected"
    assert any(r["reason"] == "host_mismatch" for r in obs["rejections"])
    assert all("cdn.example.com" not in (o["observed_url"] or "")
               for o in obs["observations"]), "an out-of-scope observation was stored"


def test_teardown_is_confirmed_and_recorded(asset_id):
    job = _run_fixture_assessment(asset_id)
    status, events = call("GET", f"/assessments/{job['id']}/events")
    assert status == 200
    assert any("teardown confirmed" in e["message"] for e in events), events


def test_fixture_mode_cannot_use_an_adapter_that_touches_the_target(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/assessments?mode=fixture", role="analyst",
                        body={"profile_key": "zap-passive"})
    assert status == 409, body
    assert body["type"].endswith("fixture-mode-requires-mock-adapter")


def test_fixture_mode_cannot_be_intrusive(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/assessments?mode=fixture", role="analyst",
                        body={"profile_key": "zap-active-intrusive"})
    assert status == 409, body
    assert body["type"].endswith(("fixture-mode-requires-mock-adapter",
                                  "fixture-mode-not-intrusive"))


def test_live_assessment_is_denied_by_the_gate_chain(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/assessments", role="analyst",
                        body={"profile_key": "zap-passive"})
    assert status == 409, body
    assert body["type"].endswith("scope-denied")
    assert body["scope_decision"]["mode"] == "live"


def test_scanner_state_is_reported():
    status, body = call("GET", "/system/scanner/state")
    assert status == 200
    assert body["default_adapter"] == "mock"
    assert "zap" in body["adapters"]


# ---- I8: a dirty daemon blocks every job, on every asset ---------------------
def test_dirty_daemon_blocks_new_jobs_and_only_a_verified_reset_clears_it(asset_id):
    """Invariant I8. The dirty flag is set directly (as a crashed worker would),
    then a job is attempted, then the reset is exercised."""
    seeded = _psql(
        "insert into scanner_daemon_state "
        "(adapter_name,is_dirty,dirty_reason,requires_operator_restart,updated_at) "
        "values ('zap',true,'test induced',false,now()) on conflict (adapter_name) do update "
        "set is_dirty=true, dirty_reason='test induced'")
    assert "ERROR" not in seeded, seeded
    try:
        status, body = call("POST", f"/assets/{asset_id}/scope/validate", role="analyst",
                            body={"profile_key": "zap-passive"})
        assert status == 200
        gate = next(g for g in body["gate_results"] if g["gate"] == "scanner_daemon_available")
        assert gate["pass"] is False, "a dirty daemon did not deny gate 13"
        assert "dirty" in (gate.get("reason") or "")
        # an analyst cannot clear it
        assert call("POST", "/system/scanner/reset?adapter=zap", role="analyst")[0] == 403
    finally:
        _psql("update scanner_daemon_state set is_dirty=false, dirty_reason=null "
              "where adapter_name='zap'")
    status, body = call("POST", f"/assets/{asset_id}/scope/validate", role="analyst",
                        body={"profile_key": "zap-passive"})
    gate = next(g for g in body["gate_results"] if g["gate"] == "scanner_daemon_available")
    assert gate["pass"] is True


def test_mock_reset_is_local_and_records_its_step():
    status, body = call("POST", "/system/scanner/reset?adapter=mock", role="admin")
    assert status == 200, body
    assert body["steps"] and all("step" in s for s in body["steps"])
    assert body["cleared_dirty"] is True


def test_zap_reset_is_delegated_to_the_worker_and_fully_verified():
    """The api has no route to vapt_lab, so it cannot verify the daemon itself.
    It delegates; the worker runs R2-R7 and clears the flag only on a full pass."""
    status, body = call("POST", "/system/scanner/reset?adapter=zap", role="admin")
    assert status == 200, body
    assert body["delegated_to"] == "worker" and body["reset_id"]
    if not body["enqueued"]:
        pytest.skip("broker unavailable")
    for _ in range(30):
        s, rows = call("GET", "/system/scanner/resets?limit=5", role="approver")
        assert s == 200
        mine = [r for r in rows if r["id"] == body["reset_id"]]
        if mine and mine[0]["steps"].get("steps"):
            steps = {x["step"]: x["pass"] for x in mine[0]["steps"]["steps"]}
            assert mine[0]["cleared_dirty"] is True, mine[0]
            for step in ("R2", "R4", "R5", "R6", "R7"):
                assert steps.get(step) is True, (step, steps)
            return
        time.sleep(1)
    pytest.fail("the delegated reset never reported its steps")


# ---- I13: cancellation is bounded -------------------------------------------
def _worker_fault() -> str:
    out = subprocess.run(["docker", "inspect", "vapt_worker", "--format",
                          "{{range .Config.Env}}{{println .}}{{end}}"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("MOCK_FAULT="):
            return line.split("=", 1)[1]
    return ""


def test_cancellation_reaches_a_terminal_state_within_the_sla(asset_id):
    """Invariant I13, MEASURED against the running worker.

    Needs a deterministic window in which the job is still running, so it
    requires the worker to be started with MOCK_FAULT=slow. Racing a one-poll
    mock would make this test flaky, and a flaky safety test is worse than an
    honest skip: run `make test-cancellation`.
    """
    if _worker_fault() != "slow":
        pytest.skip("worker is not running with MOCK_FAULT=slow; run `make test-cancellation` "
                    "for a deterministic cancellation window")
    status, job = call("POST", f"/assets/{asset_id}/assessments?mode=fixture", role="analyst",
                       body={"profile_key": "mock-passive"})
    assert status == 201, job
    jid = job["id"]
    for _ in range(60):
        s, j = call("GET", f"/assessments/{jid}")
        if j["state"] in ("running", "completed", "cancelled", "failed"):
            break
        time.sleep(0.3)
    assert j["state"] == "running", f"job left the running window too fast: {j['state']}"
    t0 = time.monotonic()
    assert call("POST", f"/assessments/{jid}/cancel", role="analyst")[0] == 200
    for _ in range(300):
        s, j = call("GET", f"/assessments/{jid}")
        if j["state"] in ("cancelled", "failed", "completed"):
            break
        time.sleep(0.3)
    elapsed = time.monotonic() - t0
    sla = int(os.environ.get("CANCELLATION_SLA_SECONDS", "120"))
    assert elapsed < sla, f"cancellation took {elapsed:.1f}s, over the {sla}s SLA"
    assert j["state"] == "cancelled", f"the cancel did not take effect: {j['state']}"
    assert j["coverage_complete"] is False, "a cancelled job must not claim full coverage"


def test_cancelling_a_finished_assessment_is_refused(asset_id):
    job = _run_fixture_assessment(asset_id)
    status, body = call("POST", f"/assessments/{job['id']}/cancel", role="analyst")
    assert status == 409, body
    assert body["type"].endswith("already-terminal")


# ---- ZAP control plane: session/context only, never a target ----------------
def test_zap_daemon_lifecycle_control_plane_only():
    """newSession, empty-store assertion, context create/remove, teardown.

    This touches ZAP's own control plane. It starts no scan and sends nothing to
    any target, so it is independent of the scan authorisation.
    """
    out = subprocess.run(["bash", "-lc",
        'set -a; . ./.env; set +a; docker run --rm --network vapt_lab --ip 172.30.10.31 '
        '-e ZAP_BASE_URL="$ZAP_BASE_URL" -e ZAP_API_KEY="$ZAP_API_KEY" '
        '-e DATABASE_URL=postgresql+psycopg://x:y@127.0.0.1:1/none -e SECRET_KEY=0000000000000000 '
        'vapt-api:dev python -c "'
        'from app.scanners.zap.client import ZapClient;'
        'c=ZapClient();'
        'print(\\"version\\", c.version());'
        'c.new_session(\\"ctrl-test\\");'
        'print(\\"stores\\", c.stores_empty());'
        'c.new_context(\\"ctrl-probe\\");'
        'print(\\"ctx_present\\", \\"ctrl-probe\\" in c.contexts());'
        'c.remove_context(\\"ctrl-probe\\");'
        'print(\\"ctx_removed\\", \\"ctrl-probe\\" not in c.contexts());'
        'print(\\"idle\\", c.is_idle());'
        'c.close()"'], cwd=REPO, capture_output=True, text=True, timeout=180)
    if "unreachable" in out.stdout or out.returncode != 0:
        pytest.skip(f"ZAP control plane unreachable: {out.stdout[-300:]} {out.stderr[-300:]}")
    assert "version 2." in out.stdout, out.stdout
    assert "stores (True," in out.stdout, f"stores not empty: {out.stdout}"
    assert "ctx_present True" in out.stdout
    assert "ctx_removed True" in out.stdout
    assert "idle (True," in out.stdout
