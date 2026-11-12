"""Invariant I4 — No scanner worker has internet access.

Runs the real isolation verification against the running lab. This is not a
mock: it asserts that TCP egress and public DNS resolution genuinely fail from
inside the ZAP and Juice Shop containers.

The failure direction is proven separately by scripts/prove_isolation_failure.sh
(M1 acceptance V3), because a check that cannot fail is not a check.
"""
from __future__ import annotations
import json, pathlib, subprocess, pytest

REPO = pathlib.Path(__file__).parents[3]


def _lab_running() -> bool:
    out = subprocess.run(["docker", "inspect", "vapt_zap", "--format", "{{.State.Running}}"],
                         capture_output=True, text=True)
    return out.stdout.strip() == "true"


@pytest.fixture(scope="module")
def isolation() -> dict:
    if not _lab_running():
        pytest.fail("I4 cannot be evaluated: the lab is not running. Run `make lab-up` first. "
                    "An unevaluated safety invariant is a failure, not a skip.")
    proc = subprocess.run(["./scripts/lab_isolation_check.sh"], cwd=REPO,
                          capture_output=True, text=True, timeout=600)
    payload = json.loads(proc.stdout)
    payload["_exit"] = proc.returncode
    return payload


def test_egress_blocked_flag(isolation):
    assert isolation["egress_blocked"] is True


def test_public_dns_contained(isolation):
    assert isolation["dns_contained"] is True


def test_every_tcp_egress_probe_blocked(isolation):
    probes = [p for p in isolation["probe_results"] if p["id"].startswith(("I2:", "I3:"))]
    assert probes, "no egress probes ran"
    failed = [p for p in probes if not p["pass"]]
    assert not failed, f"scanner containers reached the internet: {failed}"


def test_no_default_route_inside_scanner(isolation):
    p = next(p for p in isolation["probe_results"] if p["id"] == "I1b")
    assert p["pass"], f"scanner has a default route: {p}"


def test_lab_network_is_internal(isolation):
    p = next(p for p in isolation["probe_results"] if p["id"] == "I1a")
    assert p["pass"] and p["observed"] == "true"


def test_docker_socket_absent_from_scanner(isolation):
    for p in isolation["probe_results"]:
        if p["id"].startswith("I5"):
            assert p["pass"], f"docker socket exposure: {p}"
