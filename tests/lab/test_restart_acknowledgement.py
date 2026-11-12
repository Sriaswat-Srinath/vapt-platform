"""D23 — the operator restart acknowledgement: bound, single-use, short-lived,
atomically consumed, invalidated on any identity mismatch, and NEVER able to
clear the dirty flag on its own. Non-destructive (no container restarts here;
the full restart flow lives in test_lab_recovery.py)."""
from __future__ import annotations
import json, pathlib, subprocess, pytest

REPO = pathlib.Path(__file__).parents[2]
STATE = REPO / ".lab-state" / "zap-daemon-state.json"
AUDIT = REPO / ".lab-state" / "zap-daemon-audit.log"
SCRIPT = "./scripts/zap_daemon_state.sh"


def sh(*a, env=None):
    import os
    return subprocess.run(a, cwd=REPO, capture_output=True, text=True, env={**os.environ, **(env or {})})


def state() -> dict:
    return json.loads(STATE.read_text())


def ack() -> dict | None:
    return state().get("operator_restart_ack")


@pytest.fixture(autouse=True)
def _clean_ack():
    yield
    # never leave an ack lying around between tests
    if isinstance(ack(), dict):
        s = state(); s["operator_restart_ack"] = None; STATE.write_text(json.dumps(s, indent=2))


def test_ack_is_bound_to_every_required_field():
    r = sh(SCRIPT, "ack-restart", env={"OPERATOR_ID": "test-operator"})
    assert r.returncode == 0, r.stdout + r.stderr
    a = ack()
    for k in ("container_id", "container_started_at", "daemon_instance_uuid",
              "acknowledgement_nonce", "operator_identity", "issued_at", "expires_at"):
        assert a.get(k), f"acknowledgement missing {k}"
    cid, started = sh("docker", "inspect", "vapt_zap", "--format", "{{.Id}} {{.State.StartedAt}}").stdout.split()
    assert a["container_id"] == cid and a["container_started_at"] == started
    assert a["operator_identity"] == "test-operator"
    assert len(a["acknowledgement_nonce"]) == 32
    assert "does NOT clear dirty" in r.stdout


def test_ack_never_clears_dirty_on_its_own():
    sh(SCRIPT, "mark-dirty", "d23_check")
    assert state()["is_dirty"] is True
    sh(SCRIPT, "ack-restart")
    assert state()["is_dirty"] is True, "issuing an acknowledgement changed the dirty flag"
    assert isinstance(ack(), dict)
    # clean up dirty state via the real verified path (daemon is healthy, marker present)
    r = sh(SCRIPT, "reset")
    assert r.returncode == 0, r.stdout
    assert state()["is_dirty"] is False


def test_unused_ack_is_invalidated_not_carried_forward():
    sh(SCRIPT, "ack-restart")
    r = sh(SCRIPT, "reset")       # marker present -> ack not needed
    assert r.returncode == 0, r.stdout
    assert ack() is None, "an unused acknowledgement survived a reset"
    assert "not_needed_marker_present" in AUDIT.read_text()


@pytest.mark.parametrize("field,value,reason", [
    ("container_id", "0" * 64, "container_id mismatch"),
    ("container_started_at", "2000-01-01T00:00:00.000000000Z", "container_started_at mismatch"),
    ("expires_at", "2000-01-01T00:00:00+00:00", "expired"),
    ("acknowledgement_nonce", "", "missing acknowledgement_nonce"),
    ("operator_identity", "", "missing operator_identity"),
])
def test_identity_mismatch_or_expiry_invalidates_ack(field, value, reason):
    """Simulate a restart (marker absent) by pointing the stored marker at a
    context that does not exist, then tamper one bound field. R3 must FAIL,
    the ack must be removed, and dirty must remain set."""
    sh(SCRIPT, "mark-dirty", f"d23_{field}")
    sh(SCRIPT, "ack-restart")
    s = state(); s["operator_restart_ack"][field] = value
    saved_marker = s["instance_marker"]; s["instance_marker"] = "vapt-instance-does-not-exist"
    STATE.write_text(json.dumps(s, indent=2))
    r = sh(SCRIPT, "reset")
    assert r.returncode != 0, f"tampered ack ({field}) was accepted:\n{r.stdout}"
    assert reason.split()[0] in r.stdout
    assert state()["is_dirty"] is True
    assert ack() is None, "a mismatched acknowledgement was left on file"
    assert "ack_invalidated" in AUDIT.read_text()
    # restore the real marker, then clear via the verified path
    s = state(); s["instance_marker"] = saved_marker; STATE.write_text(json.dumps(s, indent=2))
    assert sh(SCRIPT, "reset").returncode == 0


def test_ack_is_single_use_and_short_lived():
    sh(SCRIPT, "ack-restart", env={"ACK_TTL_SECONDS": "1"})
    import time; time.sleep(2)
    s = state(); saved = s["instance_marker"]; s["instance_marker"] = "vapt-instance-does-not-exist"
    STATE.write_text(json.dumps(s, indent=2))
    sh(SCRIPT, "mark-dirty", "ttl")
    r = sh(SCRIPT, "reset")
    assert r.returncode != 0 and "expired" in r.stdout
    assert ack() is None
    s = state(); s["instance_marker"] = saved; STATE.write_text(json.dumps(s, indent=2))
    assert sh(SCRIPT, "reset").returncode == 0
