"""M1 lab verification — pytest wrappers so CI asserts the same facts as the
scripts, probe by probe (acceptance criteria F1-F7, I1-I13)."""
from __future__ import annotations
import json, pathlib, subprocess, pytest

REPO = pathlib.Path(__file__).parents[2]


@pytest.fixture(scope="session")
def check() -> dict:
    proc = subprocess.run(["./scripts/lab_isolation_check.sh"], cwd=REPO,
                          capture_output=True, text=True, timeout=900)
    assert proc.stdout.strip().startswith("{"), f"check produced no JSON:\n{proc.stdout}\n{proc.stderr}"
    d = json.loads(proc.stdout)
    d["_exit"] = proc.returncode
    return d


def _probe(check: dict, pid: str) -> dict:
    hits = [p for p in check["probe_results"] if p["id"] == pid or p["id"].startswith(pid + ":")]
    assert hits, f"probe {pid} did not run"
    return hits[0] if len(hits) == 1 else {"id": pid, "pass": all(h["pass"] for h in hits),
                                           "observed": [h["observed"] for h in hits],
                                           "required": hits[0]["required"], "detail": "aggregated"}


def test_overall_verdict(check):
    assert check["passed"] is True and check["_exit"] == 0, \
        [p for p in check["probe_results"] if not p["pass"]]


@pytest.mark.parametrize("pid,label", [
    ("F1",   "F1 juice shop reachable inside the lab by its alias"),
    ("F4",   "F4 workstation reaches http://127.0.0.1:3000"),
    ("I1a",  "I1 lab network is internal"),
    ("I1b",  "I1 no default route inside the scanner"),
    ("I1c",  "I1 lab subnet as configured"),
    ("I2",   "I2 egress blocked from ZAP"),
    ("I3",   "I3 egress blocked from Juice Shop"),
    ("I4a",  "I4 public DNS contained (ZAP)"),
    ("I4b",  "I4 public DNS contained (Juice Shop)"),
    ("I5c",  "I5 docker.sock absent inside the scanner"),
    ("I6a",  "I6 scanner runs non-root"),
    ("I6b",  "I6 read-only rootfs"),
    ("I6c",  "I6 capabilities dropped"),
    ("I6d",  "I6 no-new-privileges"),
    ("I6e",  "I6 pids limit"),
    ("I6f",  "I6 memory limit"),
    ("I8a",  "I8 juice shop published on loopback"),
    ("I8b",  "I8 juice shop NOT published on 0.0.0.0"),
    ("I8c",  "I8 ZAP API port NOT published to the host"),
    ("I8d",  "I8 host cannot reach 127.0.0.1:8080"),
    ("I9a",  "I9 ZAP API accepts an allowlisted in-lab client with the key"),
    ("I9b",  "I9 ZAP API rejects a request without the key"),
    ("I9c",  "I9 ZAP API rejects the host (not in api.addrs allowlist)"),
    ("I10a", "I10 alias resolves inside the lab, in-subnet"),
    ("I10b", "I10 alias does NOT resolve on the workstation"),
])
def test_probe(check, pid, label):
    p = _probe(check, pid)
    assert p["pass"], f"{label}: required={p['required']!r} observed={p['observed']!r} ({p.get('detail')})"


def test_no_host_bind_mounts_in_lab_containers(check):
    for p in check["probe_results"]:
        if p["id"].startswith("I7:"):
            assert p["pass"], f"I7 host bind mount present: {p}"


def test_subnet_conflict_refuses_startup():
    """F7 — a conflicting LAB_SUBNET must refuse, and a free one must pass."""
    import os
    bad = subprocess.run(["./scripts/lab_subnet_check.sh"], cwd=REPO, capture_output=True,
                         text=True, env={**os.environ, "LAB_SUBNET": "172.17.0.0/16"})
    assert bad.returncode != 0, f"a conflicting subnet was accepted: {bad.stdout}{bad.stderr}"
    assert "SUBNET CONFLICT" in bad.stdout
    good = subprocess.run(["./scripts/lab_subnet_check.sh"], cwd=REPO, capture_output=True,
                          text=True, env={**os.environ, "LAB_SUBNET": "172.30.10.0/24"})
    assert good.returncode == 0, good.stdout + good.stderr


def test_compose_declares_no_docker_socket_anywhere():
    """I13 — no container-control capability exists in the lab definition."""
    for f in ("docker-compose.lab.yml", "docker-compose.yml"):
        text = (REPO / f).read_text()
        assert "docker.sock" not in text, f"{f} references the Docker socket"
        assert "/var/run/docker" not in text


def test_zap_has_no_published_ports_in_compose():
    """Comments mention `ports:`; assert on the rendered config instead."""
    import json
    cfg = subprocess.run(["docker", "compose", "-f", "docker-compose.lab.yml", "config", "--format", "json"],
                         cwd=REPO, capture_output=True, text=True)
    assert cfg.returncode == 0, cfg.stderr
    services = json.loads(cfg.stdout)["services"]
    assert not services["zap"].get("ports"), f"ZAP must publish no port: {services['zap'].get('ports')}"
    live = subprocess.run(["docker", "inspect", "vapt_zap", "--format", "{{json .NetworkSettings.Ports}}"],
                          capture_output=True, text=True).stdout.strip()
    assert '"HostPort"' not in live, f"ZAP has a host port binding: {live}"


def test_zap_restart_policy_is_no():
    policy = subprocess.run(["docker", "inspect", "vapt_zap", "--format",
                             "{{.HostConfig.RestartPolicy.Name}}"], capture_output=True, text=True)
    assert policy.stdout.strip() in ("no", ""), "ZAP must not auto-restart (ADR-0008 R3 §9)"
