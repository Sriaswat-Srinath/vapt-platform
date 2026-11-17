"""M1.5 network architecture verification, probe by probe.

Wraps scripts/net_verify.sh so CI asserts the same facts. Every NET-* probe is
one test case; a probe that errors is a failure, never a skip.
"""
from __future__ import annotations
import json, pathlib, subprocess, pytest

REPO = pathlib.Path(__file__).parents[2]


def _up() -> bool:
    out = subprocess.run(["docker", "inspect", "vapt_api", "--format", "{{.State.Running}}"],
                         capture_output=True, text=True)
    return out.stdout.strip() == "true"


@pytest.fixture(scope="session")
def net() -> dict:
    if not _up():
        pytest.fail("the M1.5 app plane is not running. Run `make net-up` first. "
                    "An unevaluated network assertion is a failure, not a skip.")
    proc = subprocess.run(["./scripts/net_verify.sh"], cwd=REPO, capture_output=True,
                          text=True, timeout=1800)
    payload = proc.stdout[proc.stdout.index("{"):]
    d = json.loads(payload)
    d["_exit"] = proc.returncode
    return d


def test_overall_verdict(net):
    assert net["net_passed"] is True and net["_exit"] == 0, \
        [p for p in net["probe_results"] if not p["pass"]]


def test_result_records_ip_forward_and_host_isolation_note(net):
    """Correction 2: ip_forward recorded; no claim of complete host isolation."""
    assert net["ip_forward"] in ("0", "1"), net["ip_forward"]
    note = net["host_isolation_note"].lower()
    assert "not complete host isolation" in note
    assert "container->internet and container->lan" in note


def test_llm_test_configuration_is_the_local_standin(net):
    """Correction 3: explicit, test-only, never the real provider."""
    cfg = net["llm_test_configuration"]
    assert cfg["provider_host"] == "llm-standin"
    assert cfg["provider_port"] == 8443
    assert cfg["real_provider_contacted"] is False


def _ids(net, prefix):
    return [p for p in net["probe_results"] if p["id"].startswith(prefix)]


@pytest.mark.parametrize("prefix,label", [
    ("NET-A", "correction 5: exact network attachment sets"),
    ("NET-B", "correction 5: image digests pinned and running"),
    ("NET-C", "correction 5: environment hygiene (no LLM/proxy/credential leakage)"),
    ("NET-D", "correction 5: no 0.0.0.0 publishing"),
    ("NET-E", "correction 5: Docker socket absent"),
    ("NET-F", "correction 5: only the proxy has a default route"),
    ("NET-HG", "correction 2: host-gateway vs LAN reachability"),
    ("NET-G", "correction 4: worker airgap (internet, LAN, proxy, api)"),
    ("NET-H", "correction 4: api has no direct egress"),
    ("NET-I", "correction 4: frontend cannot reach data or proxy planes"),
    ("NET-J", "corrections 3+4: proxy ACL, bypass and abuse"),
    ("NET-K", "correction 3: ip_forward recorded; real provider never contacted"),
])
def test_probe_group(net, prefix, label):
    group = _ids(net, prefix)
    assert group, f"no probes ran for {prefix}"
    failing = [(p["id"], p["required"], p["observed"], p["detail"]) for p in group if not p["pass"]]
    assert not failing, f"{label}: {failing}"


def test_worker_cannot_reach_the_api_from_core(net):
    """Correction 5: api binds its edge interface only, proven from the worker."""
    p = next(x for x in net["probe_results"] if x["id"] == "NET-G5")
    assert p["pass"] and p["observed"] == "ECONNREFUSED", p


def test_proxy_denials_are_logged(net):
    for pid in ("NET-J10", "NET-J10b"):
        assert next(x for x in net["probe_results"] if x["id"] == pid)["pass"]


def test_no_probe_was_malformed(net):
    bad = [p for p in net["probe_results"] if "MALFORMED" in p["detail"]]
    assert not bad, bad


def test_probe_ids_do_not_collide_with_invariants(net):
    """Correction 1: NET-* namespace cannot be confused with invariants I1..I14."""
    import re
    for p in net["probe_results"]:
        assert p["id"].startswith("NET-"), p["id"]
        assert not re.fullmatch(r"I\d+[a-z]?", p["id"]), f"collides with an invariant id: {p['id']}"
