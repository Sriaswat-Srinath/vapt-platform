"""M1 recovery verification — destructive, scoped, and reverted.

Release blockers covered here:
  * ZAP crash ⇒ daemon remains down, no automatic restart.
  * Dirty daemon ⇒ cannot be cleared without full verification.
  * Reset ⇒ cannot delete unrelated developer data.

Run explicitly: pytest tests/lab/test_lab_recovery.py
"""
from __future__ import annotations
import json, pathlib, subprocess, time, pytest

REPO = pathlib.Path(__file__).parents[2]
STATE = REPO / ".lab-state" / "zap-daemon-state.json"


def sh(*args, **kw):
    return subprocess.run(args, cwd=REPO, capture_output=True, text=True, **kw)


def running(name: str) -> str:
    return sh("docker", "inspect", name, "--format", "{{.State.Running}}").stdout.strip()


def test_zap_crash_leaves_daemon_down_then_operator_restores():
    """A killed daemon must stay down: it must not return with a clean session."""
    assert running("vapt_zap") == "true"
    sh("docker", "kill", "vapt_zap")
    for _ in range(6):                      # 30s: ample time for any restart policy to fire
        time.sleep(5)
        assert running("vapt_zap") == "false", "ZAP restarted automatically — restart policy is wrong"
    # Operator-performed restart via the DOCUMENTED path (the platform itself has
    # no Docker socket), followed by the verification-gated reset.
    out = sh("make", "lab-zap-restart", timeout=900)
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-1000:]
    assert running("vapt_zap") == "true"
    reset = sh("make", "zap-reset", timeout=300)
    assert reset.returncode == 0, reset.stdout[-2000:]


def _wait_healthy(timeout_s: int = 120) -> None:
    for _ in range(timeout_s // 5):
        if sh("docker", "inspect", "vapt_zap", "--format",
              "{{.State.Health.Status}}").stdout.strip() == "healthy":
            return
        time.sleep(5)
    raise AssertionError("ZAP did not become healthy")


def test_dirty_daemon_cannot_be_cleared_without_verification():
    """ADR-0008 R3 §10 — the dirty flag clears only when R2..R7 all pass."""
    # Establish a verified baseline so an instance marker exists.
    _wait_healthy()
    base = sh("./scripts/zap_daemon_state.sh", "reset")
    assert base.returncode == 0, "baseline verification failed: " + base.stdout
    assert json.loads(STATE.read_text())["instance_marker"] not in (None, "null")

    sh("./scripts/zap_daemon_state.sh", "mark-dirty", "test_induced_dirty")
    assert json.loads(STATE.read_text())["is_dirty"] is True

    # 1. Daemon unreachable -> reset FAILS at R2 and must NOT clear the flag.
    sh("docker", "stop", "vapt_zap")
    failed = sh("./scripts/zap_daemon_state.sh", "reset")
    state = json.loads(STATE.read_text())
    assert failed.returncode != 0, "reset reported success against an unreachable daemon"
    assert state["is_dirty"] is True, "dirty flag cleared without verification"
    assert state["requires_operator_restart"] is True
    assert "RETAINED" in failed.stdout and "R2" in failed.stdout

    # 2. UNACKNOWLEDGED restart -> the instance marker is gone, so daemon state is
    #    unverifiable. Reset must still refuse, at R3. This is the stronger property:
    #    simply restarting the container must never launder a dirty daemon.
    sh("docker", "compose", "-f", "docker-compose.lab.yml", "start", "zap")
    _wait_healthy()
    unauth = sh("./scripts/zap_daemon_state.sh", "reset")
    state = json.loads(STATE.read_text())
    assert unauth.returncode != 0, "an unexplained restart cleared the dirty flag"
    assert state["is_dirty"] is True
    assert "R3" in unauth.stdout and "NOT authorised" in unauth.stdout

    # 3. Documented operator path (ADR-0008 R3 §11): restart is one step and the
    #    verification-gated reset is a SEPARATE explicit step. The restart alone
    #    must not clear the flag.
    restarted = sh("make", "lab-zap-restart", timeout=900)
    assert restarted.returncode == 0, restarted.stdout[-2000:] + restarted.stderr[-1000:]
    assert json.loads(STATE.read_text())["is_dirty"] is True, \
        "a container restart alone cleared the dirty flag"

    reset = sh("make", "zap-reset", timeout=300)
    assert reset.returncode == 0, reset.stdout[-2000:] + reset.stderr[-1000:]
    state = json.loads(STATE.read_text())
    assert state["is_dirty"] is False, "verified operator recovery did not clear the flag"
    assert state["operator_restart_ack"] is None, "acknowledgement must be single-use (consumed)"
    for step in ("R2", "R3", "R4", "R5", "R6", "R7"):
        assert step in reset.stdout

    # 4. The consumed acknowledgement cannot be replayed: a second unauthorised
    #    restart must fail verification again.
    sh("./scripts/zap_daemon_state.sh", "mark-dirty", "replay_check")
    sh("docker", "compose", "-f", "docker-compose.lab.yml", "restart", "zap")
    _wait_healthy()
    replay = sh("./scripts/zap_daemon_state.sh", "reset")
    assert replay.returncode != 0, "a consumed acknowledgement was replayed"
    assert json.loads(STATE.read_text())["is_dirty"] is True
    sh("make", "lab-zap-restart", timeout=900); sh("make", "zap-reset", timeout=300)


def test_dirty_state_transitions_are_audited():
    log = REPO / ".lab-state" / "zap-daemon-audit.log"
    assert log.exists(), "no audit log for daemon state transitions"
    text = log.read_text()
    for action in ("mark_dirty", "reset_failed", "ack_issued", "ack_consumed", "reset_verified"):
        assert f"action={action}" in text, f"transition {action} never audited"


def test_reset_never_offers_a_force_path():
    """There must be no way to clear dirty state without verification."""
    src = pathlib.Path(REPO / "scripts" / "zap_daemon_state.sh").read_text()
    for forbidden in ("--force", "-f)", "force)", "FORCE"):
        assert forbidden not in src, f"reset exposes a bypass: {forbidden}"
    bogus = sh("./scripts/zap_daemon_state.sh", "clear")
    assert bogus.returncode != 0, "an undocumented subcommand cleared state"


def test_compose_stacks_use_distinct_project_names():
    """A shared project name let `lab-reset --remove-orphans` delete the whole
    application plane. The two stacks must stay in separate projects."""
    import re
    names = {}
    for f in ("docker-compose.yml", "docker-compose.lab.yml"):
        m = re.search(r"(?m)^name:\s*(\S+)", (REPO / f).read_text())
        assert m, f"{f} declares no project name"
        names[f] = m.group(1)
    assert len(set(names.values())) == 2, f"compose projects collide: {names}"


def test_lab_reset_does_not_remove_the_application_plane():
    """Regression: `make lab-reset` must leave the M1.5/M2 app plane running."""
    app = ["vapt_api", "vapt_worker", "vapt_frontend", "vapt_postgres",
           "vapt_redis", "vapt_egress_proxy"]
    before = {c: running(c) for c in app}
    if not any(v == "true" for v in before.values()):
        pytest.skip("application plane is not running (make net-up) — nothing to protect")
    assert sh("make", "lab-reset", timeout=900).returncode == 0
    after = {c: running(c) for c in app}
    lost = [c for c in app if before[c] == "true" and after[c] != "true"]
    assert not lost, f"lab-reset removed application-plane containers: {lost}"


def test_lab_reset_cannot_delete_unrelated_developer_data():
    """`make lab-reset` is scoped to compose project `vapt` only."""
    sh("docker", "volume", "create", "devdata_sentinel_vol")
    sh("docker", "network", "create", "devdata_sentinel_net")
    pre_networks = set(sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split())
    pre_volumes = set(sh("docker", "volume", "ls", "--format", "{{.Name}}").stdout.split())
    pre_images = len(sh("docker", "images", "-q").stdout.split())
    try:
        reset = sh("make", "lab-reset", timeout=900)
        assert reset.returncode == 0, reset.stdout[-3000:] + reset.stderr[-2000:]
        post_networks = set(sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split())
        post_volumes = set(sh("docker", "volume", "ls", "--format", "{{.Name}}").stdout.split())
        assert "devdata_sentinel_vol" in post_volumes, "reset deleted an unrelated volume"
        assert "devdata_sentinel_net" in post_networks, "reset deleted an unrelated network"
        unrelated_lost = {n for n in pre_networks - post_networks if not n.startswith("vapt")}
        assert not unrelated_lost, f"reset removed unrelated networks: {unrelated_lost}"
        vols_lost = {v for v in pre_volumes - post_volumes if not v.startswith("vapt")}
        assert not vols_lost, f"reset removed unrelated volumes: {vols_lost}"
        assert len(sh("docker", "images", "-q").stdout.split()) == pre_images, "reset removed images"
        assert "prune" not in (REPO / "Makefile").read_text(), "Makefile must never prune"
    finally:
        sh("docker", "volume", "rm", "-f", "devdata_sentinel_vol")
        sh("docker", "network", "rm", "devdata_sentinel_net")
