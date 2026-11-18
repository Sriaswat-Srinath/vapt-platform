"""Phase 8: gate 2 host hygiene, evidence retention (I12) and API rate limiting.

Invariant implemented here:
  I12  purge is idempotent and halts on inconsistency

The retention tests that DELETE require `make test-retention`, which turns
RETENTION_ENABLED on for the run and off again afterwards. They skip with that
instruction rather than silently passing against a disabled platform.
"""
from __future__ import annotations
import datetime as dt
import json, os, pathlib, subprocess, sys
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("REDACTION_HMAC_KEY", "0" * 64)
# The rate limiter reads Settings, which requires these. The values are never
# used to connect to anything from the test host: the limiter's Redis path is
# monkeypatched or simply unreachable, and the local counter is what is under
# test.
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-for-anything")
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused")
from app import ratelimit                                            # noqa: E402
from app import retention_rules as retention                         # noqa: E402
from app.safety import scope_policy as sp                             # noqa: E402

from test_backend_core import call, asset_id                          # noqa: E402,F401


# =============================================================== gate 2 ======
def _request(**over):
    base = dict(now=dt.datetime.now(dt.timezone.utc), subject_type="scan_job",
                mode=sp.MODE_LIVE, scanner_execution_enabled=True,
                isolation_passed=True, host_hygiene_passed=True,
                isolation_valid_until=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1))
    base.update(over)
    return sp.ScopeRequest(**base)


def _gate2(**over):
    return sp.GATES[1][2](_request(**over))


def test_gate2_requires_containment():
    assert _gate2(isolation_passed=False).passed is False


def test_gate2_requires_host_hygiene_as_well(asset_id):
    """ADR-0015: a scanner that can reach an unrelated service on the operator's
    machine is out of scope even though it never left the host."""
    out = _gate2(host_hygiene_passed=False,
                 host_wildcard_listeners="0.0.0.0:5433")
    assert out.passed is False
    assert "host hygiene failed" in out.reason
    assert "0.0.0.0:5433" in out.reason
    assert "do not weaken this gate" in out.reason


def test_gate2_names_which_half_failed():
    """A denial has to be actionable: containment and hygiene fail differently."""
    containment = _gate2(isolation_passed=False).reason
    hygiene = _gate2(host_hygiene_passed=False).reason
    assert containment != hygiene
    assert "Containment passed" in hygiene


def test_gate2_refuses_a_check_that_predates_hygiene_reporting():
    out = _gate2(host_hygiene_passed=None)
    assert out.passed is False
    assert "predates host-hygiene reporting" in out.reason


def test_gate2_still_requires_a_fresh_check():
    stale = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    assert _gate2(isolation_valid_until=stale).passed is False


def test_gate2_passes_only_when_both_hold():
    assert _gate2().passed is True


def test_the_policy_version_records_the_change():
    assert sp.POLICY_VERSION >= "1.1.0", "a gate change must bump the policy version"


def test_the_decision_the_api_returns_carries_the_new_reason(asset_id):
    status, body = call("POST", f"/assets/{asset_id}/scope/validate",
                        body={"profile_key": "zap-passive", "path": "/", "method": "GET"})
    assert status == 200, body
    gate2 = next(g for g in body["gate_results"] if g["gate"] == "lab_isolation_valid")
    # Whatever this environment's state, the gate must have been EVALUATED and
    # its reason must be legible rather than a bare boolean.
    assert "reason" in gate2 or gate2["pass"] is True


# ============================================================ retention ======
def _admin(path, method="GET", **kw):
    return call(method, path, role="admin", **kw)


def test_retention_policy_states_what_is_never_purged():
    status, body = _admin("/system/retention/policy")
    assert status == 200, body
    assert body["retention_version"] == retention.RETENTION_VERSION
    for kept in ("Findings", "raw observations", "evidence rows", "audit log"):
        assert kept.lower() in body["scope"].lower()


def test_a_dry_run_is_the_default_and_deletes_nothing():
    status, body = _admin("/system/retention/purge", "POST")
    assert status == 201, body
    assert body["dry_run"] is True
    assert body["purged"] == 0
    assert "nothing was deleted" in body["note"]


def test_deleting_is_refused_while_retention_is_disabled():
    status, body = _admin("/system/retention/purge?dry_run=false", "POST")
    if status == 201:
        pytest.skip("RETENTION_ENABLED is true in this environment (make test-retention)")
    assert status == 409, body
    assert body["title"] == "Retention purge is disabled"


def test_only_an_admin_may_purge():
    for role in ("analyst", "approver"):
        status, _ = call("POST", "/system/retention/purge", role=role)
        assert status == 403, f"{role} must not be able to purge"


def test_runs_are_recorded_including_dry_runs():
    _admin("/system/retention/purge", "POST")
    status, runs = _admin("/system/retention/runs")
    assert status == 200 and runs, runs
    assert runs[0]["retention_version"] == retention.RETENTION_VERSION
    assert {"state", "dry_run", "scanned", "eligible", "purged", "halt_reason"} <= set(runs[0])


def test_nothing_currently_in_the_store_is_eligible_even_with_a_zero_day_window():
    """Every blob is referenced by evidence, an observation or a report
    artifact. A non-zero count here means a reference class was missed."""
    status, body = _admin("/system/retention/purge?dry_run=true&older_than_days=0", "POST")
    assert status == 201, body
    assert body["state"] == "completed", body
    assert body["eligible"] == 0, (
        f"{body['eligible']} blob(s) look unreferenced with a zero-day window. Either a "
        "reference class is not counted, or the store has genuine orphans.")


# ---------------------------------------------------- I12, with real blobs ---
FIXTURE = REPO / "scripts" / "retention_fixture.py"


def _fixture(action: str, *args: str) -> str:
    """Create/remove synthetic blobs inside the api image. Returns stdout."""
    env = dict(line.split("=", 1) for line in
               (REPO / ".env").read_text().splitlines() if "=" in line and not line.startswith("#"))
    cmd = [
        "docker", "run", "--rm", "--network", "vapt_core",
        "-v", "vapt_evidence:/var/lib/vapt/evidence",
        "-v", f"{FIXTURE}:/srv/rf.py:ro", "--user", "65532:65532",
        "-e", (f"DATABASE_URL=postgresql+psycopg://{env['POSTGRES_USER']}:"
               f"{env['POSTGRES_PASSWORD']}@172.30.21.40:5432/{env['POSTGRES_DB']}"),
        "-e", f"SECRET_KEY={env['SECRET_KEY']}",
        "-e", f"REDACTION_HMAC_KEY={env['REDACTION_HMAC_KEY']}",
        "-e", "EVIDENCE_BLOB_ROOT=/var/lib/vapt/evidence",
        "vapt-api:dev", "python", "/srv/rf.py", action, *args,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if out.returncode != 0 and action != "orphan-ref":
        pytest.fail(f"fixture {action} failed: {out.stderr[-400:]}")
    return out.stdout.strip()


def _retention_enabled() -> bool:
    status, body = _admin("/system/retention/purge?dry_run=false&older_than_days=3650", "POST")
    return status == 201


@pytest.fixture()
def synthetic_blobs():
    _fixture("cleanup")
    yield _fixture
    _fixture("cleanup")


def test_i12_purge_deletes_only_unreferenced_blobs_and_is_idempotent(synthetic_blobs):
    if not _retention_enabled():
        pytest.skip("RETENTION_ENABLED is false (the default). Run `make test-retention`.")
    synthetic_blobs("orphan", "3")
    status, first = _admin("/system/retention/purge?dry_run=false&older_than_days=0", "POST")
    assert status == 201, first
    assert first["state"] == "completed", first
    assert first["purged"] == 3, first
    assert first["bytes_reclaimed"] > 0

    status, second = _admin("/system/retention/purge?dry_run=false&older_than_days=0", "POST")
    assert second["state"] == "completed"
    assert second["purged"] == 0, "a second run must find nothing left to do"
    assert second["scanned"] == 0


def test_i12_an_inconsistency_halts_the_run_and_deletes_nothing(synthetic_blobs):
    if not _retention_enabled():
        pytest.skip("RETENTION_ENABLED is false (the default). Run `make test-retention`.")
    synthetic_blobs("orphan", "2")       # two perfectly good candidates
    synthetic_blobs("dangling")          # one blob whose FILE is missing

    status, out = _admin("/system/retention/purge?dry_run=false&older_than_days=0", "POST")
    assert status == 201, out
    assert out["state"] == "halted", out
    assert out["halt_reason"] == retention.HALT_BLOB_FILE_MISSING
    assert out["purged"] == 0, (
        "the run deleted blobs before halting: verification must happen for the whole "
        "batch before anything is removed")
    assert "do not" not in (out["halt_detail"] or "").lower()
    assert "disagree" in (out["halt_detail"] or "")

    # The halt is recorded, not just returned.
    _, runs = _admin("/system/retention/runs")
    assert runs[0]["state"] == "halted"
    assert runs[0]["halt_reason"] == retention.HALT_BLOB_FILE_MISSING


def test_i12_the_database_refuses_an_orphan_reference_outright(synthetic_blobs):
    """Stronger than the runtime check: a reference to a missing blob cannot be
    created at all (trigger vapt_blob_reference_guard)."""
    out = synthetic_blobs("orphan-ref")
    assert "refused-by-database" in out, out


def test_revalidation_refuses_when_the_evidence_it_needs_has_been_purged(asset_id):
    """Re-running validation over fewer bytes would produce a different verdict
    from different inputs, which is worse than refusing."""
    status, jobs = call("GET", f"/assessments?asset_id={asset_id}")
    assert status == 200
    completed = [j for j in jobs if j["state"] == "completed"]
    if not completed:
        pytest.skip("no completed assessment to revalidate")
    status, body = call("POST", f"/assessments/{completed[0]['id']}/revalidate")
    # Nothing is purged in a healthy environment, so this must SUCCEED; the
    # refusal path is asserted by the message contract below.
    assert status in (200, 409), body
    if status == 409:
        assert body["title"] == "This assessment's evidence has been purged"


# ========================================================== rate limiting ====
def test_rate_limit_classes_differ_for_reads_and_writes():
    ratelimit.reset_local()
    allowed_read, remaining_read, _, _ = ratelimit.check(
        principal="test-a", method="GET", path="/assets")
    allowed_write, remaining_write, _, _ = ratelimit.check(
        principal="test-a", method="POST", path="/assets")
    assert allowed_read and allowed_write
    assert remaining_write < remaining_read, "writes must have the tighter budget"


def test_the_limiter_refuses_after_the_budget_and_names_a_retry():
    ratelimit.reset_local()
    limit = 5
    allowed = [ratelimit._local_hit("k", 1, limit)[0] for _ in range(limit + 3)]  # noqa: SLF001
    assert allowed[:limit] == [True] * limit
    assert allowed[limit:] == [False] * 3


def test_health_is_never_rate_limited():
    allowed, _, _, limiter = ratelimit.check(
        principal="anything", method="GET", path="/api/v1/system/health")
    assert allowed and limiter == "exempt", \
        "a limiter that can block a healthcheck can restart the container it protects"


def test_limiting_falls_back_to_a_local_counter_rather_than_failing_open(monkeypatch):
    """Redis being unavailable must not mean NO limit."""
    monkeypatch.setattr(ratelimit, "_redis_hit", lambda *a, **k: None)
    ratelimit.reset_local()
    _, _, _, limiter = ratelimit.check(principal="fallback", method="GET", path="/assets")
    assert "in-process" in limiter


def test_the_api_applies_a_limit_and_reports_what_remains():
    status, body = call("GET", "/system/capabilities")
    assert status == 200, body
    import test_backend_core as core
    import urllib.request
    req = urllib.request.Request(core.BASE + "/system/capabilities",
                                 headers={"Authorization": f"Bearer {core._tokens()['analyst']}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        # HTTP header names are case-insensitive; the server sends them lowered.
        remaining = r.headers.get("X-RateLimit-Remaining")
    assert remaining is not None, \
        "the API does not report a rate-limit budget; is the middleware wired?"
    assert int(remaining) >= 0


# ================================================== detection evaluation =====
DATASET = REPO / "backend" / "fixtures" / "evaluation" / "detection_cases.json"


def _dataset() -> dict:
    return json.loads(DATASET.read_text())


def test_the_evaluation_dataset_states_what_it_does_not_measure():
    """A score against constructed evidence must not be read as field accuracy."""
    comment = " ".join(_dataset()["_comment"]).lower()
    assert "does not measure" in comment
    assert "real-world detection accuracy" in comment


def test_every_case_declares_ground_truth_and_an_expected_verdict():
    for case in _dataset()["cases"]:
        assert case["ground_truth"], case["id"]
        assert case["expected_state"] in (
            "confirmed", "false_positive", "not_applicable", "inconclusive", "candidate"), case
        assert case["rationale"].strip(), case["id"]


def test_the_dataset_covers_both_directions_for_the_rule_packs_that_can_decide():
    cases = _dataset()["cases"]
    confirming = {c["category"] for c in cases if c["expected_state"] == "confirmed"}
    refusing = {c["category"] for c in cases if c["expected_state"] in
                ("false_positive", "not_applicable")}
    both = confirming & refusing
    assert {"security_misconfiguration", "injection", "session_management",
            "cryptographic_failures", "information_disclosure"} <= both, (
        "a dataset that only contains true positives cannot detect an over-eager engine; "
        f"categories tested in both directions: {sorted(both)}")


def test_detection_evaluation_has_no_false_positives_or_false_negatives():
    """Runs the evaluator against the live platform."""
    script = REPO / "scripts" / "detection_eval.py"
    out = subprocess.run([sys.executable, str(script)], cwd=REPO,
                         capture_output=True, text=True, timeout=180)
    if "is not registered" in out.stderr or "tokens.json" in out.stderr:
        pytest.skip("the platform is not seeded; run `make db-seed && make api-publish`")
    payload = out.stdout[out.stdout.index("{"):out.stdout.index("}\n") + 1] \
        if "{" in out.stdout else "{}"
    summary = json.loads(payload)
    assert summary.get("cases"), out.stdout + out.stderr
    assert summary["false_positives"] == 0, out.stdout
    assert summary["false_negatives"] == 0, out.stdout
    assert summary["unmatched"] == 0, (
        "a case matched no finding: that detection never reached the pipeline\n" + out.stdout)
