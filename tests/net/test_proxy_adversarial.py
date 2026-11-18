"""Adversarial tests for the egress proxy — it is a security boundary.

Covers the owner's Critical-1 checklist directly:
  1. hostname validated before any connection is opened
  2. the proxy resolves hostnames itself
  3. the connection uses the VALIDATED address (no second resolution)
  4. IPv4 / IPv6 / alternative IP representations
  5. alternative CONNECT syntax cannot bypass the allowlist
  6. malformed requests rejected safely
  7. connection limits and timeouts prevent resource exhaustion
plus source enforcement and the internal-address check, each proven against a
running proxy rather than by reading the source.
"""
from __future__ import annotations
import importlib.util, json, os, pathlib, subprocess, time
import pytest

REPO = pathlib.Path(__file__).parents[2]
PROXY_SRC = REPO / "lab" / "egress-proxy" / "proxy.py"
PROXY_IP, PROXY_PORT = "172.30.22.60", 3128
API = "vapt_api"
EGRESS_NET, CORE_NET = "vapt_egress", "vapt_core"


def sh(*a, **kw):
    return subprocess.run(a, cwd=REPO, capture_output=True, text=True, **kw)


def _running(name: str) -> bool:
    return sh("docker", "inspect", name, "--format", "{{.State.Running}}").stdout.strip() == "true"


pytestmark = pytest.mark.skipif(not _running("vapt_egress_proxy"),
                                reason="app plane not running (make net-up)")


@pytest.fixture(scope="module")
def mod():
    """Import the proxy module to unit-test its pure policy function."""
    os.environ.setdefault("PROXY_BIND_IP", "127.0.0.1")
    os.environ.setdefault("EGRESS_ALLOWLIST", "llm-standin:8443")
    spec = importlib.util.spec_from_file_location("vapt_proxy", PROXY_SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def request_via_proxy(request_line: str, *, container: str = API, extra: str = "") -> str:
    """Send one raw request line to the proxy from inside a container."""
    payload = request_line + "\r\n" + extra + "\r\n"
    code = (
        "import socket\n"
        "s=socket.socket(); s.settimeout(8)\n"
        f"s.connect(('{PROXY_IP}',{PROXY_PORT}))\n"
        f"s.sendall({payload.encode()!r})\n"
        "import sys\n"
        "try:\n"
        "    d=s.recv(512).decode('latin-1','replace')\n"
        "    print(d.split('\\r\\n')[0].strip() or 'EMPTY')\n"
        "    print([l for l in d.split('\\r\\n') if l.lower().startswith('x-egress-deny-reason')])\n"
        "except OSError as e: print('ERR '+e.__class__.__name__)\n"
        "finally: s.close()\n"
    )
    out = sh("docker", "exec", container, "python3", "-c", code)
    return out.stdout.strip()


# ---- 1, 4, 5, 6: policy function against hostile targets -----------------------
@pytest.mark.parametrize("target,reason", [
    ("llm-standin", "no_port_in_target"),
    (":8443", "empty_host"),
    ("llm-standin:8443/", "non_numeric_port"),
    ("llm-standin:0", "port_out_of_range"),
    ("llm-standin:99999", "port_out_of_range"),
    ("llm-standin:08443", "non_canonical_port"),
    ("llm-standin:84 43", "non_numeric_port"),
    ("http://llm-standin:8443", "malformed_host"),
    ("user@llm-standin:8443", "malformed_host"),
    ("llm-standin:8443@evil.com:443", "malformed_host"),
    ("[::1]:8443", "malformed_host"),
    ("::1:8443", "malformed_host"),
    ("llm-standin::8443", "malformed_host"),
    ("llm-standin.:8443", "malformed_host"),
    ("2130706433:8443", "ambiguous_numeric_host"),
    ("0x7f000001:8443", "ambiguous_numeric_host"),
])
def test_policy_refuses_hostile_target_forms(mod, target, reason):
    verdict = mod.validate_target(target)
    assert verdict == reason, f"{target!r} -> {verdict!r}, expected {reason!r}"


def test_policy_accepts_only_the_canonical_allowlisted_form(mod):
    host, port = mod.validate_target("llm-standin:8443")
    assert f"{host.lower()}:{port}" in mod.ALLOWLIST
    # A valid but non-allowlisted destination parses and is then refused by policy.
    host, port = mod.validate_target("evil.example:8443")
    assert f"{host.lower()}:{port}" not in mod.ALLOWLIST


# ---- 5, 6: live refusals over the wire ------------------------------------------
@pytest.mark.parametrize("line,expect", [
    ("CONNECT llm-standin:443 HTTP/1.1", "destination_not_allowlisted"),
    ("CONNECT example.com:443 HTTP/1.1", "destination_not_allowlisted"),
    ("CONNECT 172.30.21.40:5432 HTTP/1.1", "destination_not_allowlisted"),
    ("GET http://llm-standin:8443/ HTTP/1.1", "method_not_connect"),
    ("POST http://llm-standin:8443/v1 HTTP/1.1", "method_not_connect"),
    ("connect llm-standin:8443 HTTP/1.1", "method_not_connect"),
    ("CONNECT llm-standin:8443 HTTP/0.9", "unsupported_http_version"),
    ("CONNECT", "malformed_request_line"),
    ("CONNECT llm-standin:8443", "malformed_request_line"),
    # splits into three tokens, so it is refused at the method check instead
    ("\x00\x01\x02 garbage \xff", "method_not_connect"),
    ("A B", "malformed_request_line"),
    ("CONNECT llm-standin:8443 HTTP/1.1 extra", "malformed_request_line"),
])
def test_live_proxy_refuses(line, expect):
    out = request_via_proxy(line)
    assert "200" not in out.split("\n")[0], f"request was ALLOWED: {line!r} -> {out}"
    assert expect in out, f"{line!r} -> {out} (expected reason {expect})"


def test_header_flood_is_refused():
    out = request_via_proxy("CONNECT llm-standin:8443 HTTP/1.1",
                            extra="X-Pad: " + "A" * 9000 + "\r\n")
    assert "431" in out or "header_too_large" in out, out


def test_too_many_header_lines_refused():
    out = request_via_proxy("CONNECT llm-standin:8443 HTTP/1.1",
                            extra="".join(f"X-H{i}: v\r\n" for i in range(80)))
    assert "431" in out or "too_many_header_lines" in out, out


# ---- 2, 3: resolve itself, then connect to the address it validated -------------
def test_connection_uses_the_validated_address():
    """The destination connected to must be the one policy authorised."""
    sh("docker", "exec", API, "python3", "-c",
       "import socket\n"
       f"s=socket.socket(); s.settimeout(8); s.connect(('{PROXY_IP}',{PROXY_PORT}))\n"
       "s.sendall(b'CONNECT llm-standin:8443 HTTP/1.1\\r\\nHost: llm-standin\\r\\n\\r\\n')\n"
       "s.recv(128); s.sendall(b'PING\\n'); s.recv(64); s.close()")
    time.sleep(1)
    logs = sh("docker", "logs", "vapt_egress_proxy").stdout.splitlines()
    allows = [json.loads(l) for l in logs if l.startswith("{") and '"verdict": "allow"' in l]
    assert allows, "no allow decision logged"
    a = allows[-1]
    assert a["destination"] == "llm-standin:8443"
    assert a["resolved"] == ["172.30.23.70"], a
    # connected_to proves the dialled address is the validated one, not a re-resolution
    assert a["connected_to"] == "172.30.23.70:8443", a


# ---- source enforcement (defence in depth beyond network isolation) -------------
def test_proxy_refuses_a_non_allowlisted_source():
    """A container on vapt_egress with a different address must be refused even
    though it can reach the port."""
    img = sh("docker", "inspect", API, "--format", "{{.Config.Image}}").stdout.strip()
    out = sh("docker", "run", "--rm", "--network", EGRESS_NET, "--ip", "172.30.22.99",
             "--entrypoint", "python3", img, "-c",
             "import socket\n"
             f"s=socket.socket(); s.settimeout(8); s.connect(('{PROXY_IP}',{PROXY_PORT}))\n"
             "s.sendall(b'CONNECT llm-standin:8443 HTTP/1.1\\r\\n\\r\\n')\n"
             "print(s.recv(256).decode('latin-1','replace').split('\\r\\n')[0])\n"
             "s.close()", timeout=120)
    assert "200" not in out.stdout, f"a non-allowlisted source was granted a tunnel: {out.stdout}"
    assert "403" in out.stdout, out.stdout + out.stderr


# ---- internal-address check, independent of the allowlist ------------------------
def test_allowlisted_name_resolving_internally_is_refused():
    """Run a throwaway proxy whose allowlist names an INTERNAL service. The
    address check must refuse it, proving the check is not merely the allowlist."""
    img = sh("docker", "inspect", API, "--format", "{{.Config.Image}}").stdout.strip()
    name = "vapt_proxy_probe"
    sh("docker", "rm", "-f", name)
    try:
        up = sh("docker", "run", "-d", "--name", name, "--network", CORE_NET,
                "--ip", "172.30.21.99",
                "-v", f"{PROXY_SRC}:/app/proxy.py:ro",
                "-e", "PROXY_BIND_IP=172.30.21.99",
                "-e", "EGRESS_ALLOWLIST=postgres:5432",      # deliberately internal
                "-e", "INTERNAL_DENY_CIDRS=172.30.20.0/24,172.30.21.0/24,172.30.22.0/24,172.30.10.0/24",
                "--entrypoint", "python3", img, "/app/proxy.py", timeout=120)
        assert up.returncode == 0, up.stderr
        time.sleep(2)
        out = sh("docker", "run", "--rm", "--network", CORE_NET, "--entrypoint", "python3", img, "-c",
                 "import socket\n"
                 "s=socket.socket(); s.settimeout(8); s.connect(('172.30.21.99',3128))\n"
                 "s.sendall(b'CONNECT postgres:5432 HTTP/1.1\\r\\n\\r\\n')\n"
                 "d=s.recv(256).decode('latin-1','replace')\n"
                 "print(d.split('\\r\\n')[0]); print([l for l in d.split('\\r\\n') if 'Deny-Reason' in l])\n"
                 "s.close()", timeout=120)
        assert "200" not in out.stdout, f"an internal destination was tunnelled: {out.stdout}"
        assert "resolves_into_internal_network" in out.stdout, out.stdout + out.stderr
    finally:
        sh("docker", "rm", "-f", name)


# ---- 7: capacity and timeouts ------------------------------------------------------
def test_capacity_limit_refuses_with_503():
    """Open more simultaneous connections than MAX_CONCURRENT_TUNNELS and expect
    503 rather than unbounded thread growth."""
    code = (
        "import socket\n"
        "ok=0; refused=0; socks=[]\n"
        "for i in range(40):\n"
        "    s=socket.socket(); s.settimeout(5)\n"
        "    try:\n"
        f"        s.connect(('{PROXY_IP}',{PROXY_PORT}))\n"
        "        socks.append(s)\n"
        "    except OSError:\n"
        "        refused+=1; continue\n"
        "for s in socks:\n"
        "    try:\n"
        "        d=s.recv(64)\n"
        "        if b'503' in d: refused+=1\n"
        "    except OSError: pass\n"
        "print('refused503_or_dropped=',refused)\n"
        "for s in socks: s.close()\n"
    )
    out = sh("docker", "exec", API, "python3", "-c", code, timeout=180)
    assert "refused503_or_dropped=" in out.stdout, out.stdout + out.stderr
    n = int(out.stdout.split("=")[1].strip())
    assert n > 0, "no connection was refused: the capacity limit is not enforced"
    # the proxy must still be serving afterwards
    assert "200" in request_via_proxy("CONNECT llm-standin:8443 HTTP/1.1").split("\n")[0]


def test_limits_are_declared_at_startup():
    logs = sh("docker", "logs", "vapt_egress_proxy").stdout.splitlines()
    start = [json.loads(l) for l in logs if l.startswith("{") and '"event": "listening"' in l]
    assert start, "no startup record"
    lim = start[-1]["limits"]
    for k in ("max_concurrent", "max_tunnel_seconds", "max_tunnel_bytes",
              "idle_timeout", "header_timeout", "max_header_bytes"):
        assert isinstance(lim[k], int) and lim[k] > 0, lim
    assert start[-1]["allowed_clients"] == ["172.30.22.20/32"], start[-1]
    assert start[-1]["allowlist"] == ["llm-standin:8443"], start[-1]


def test_proxy_refuses_to_start_without_an_allowlist():
    img = sh("docker", "inspect", API, "--format", "{{.Config.Image}}").stdout.strip()
    out = sh("docker", "run", "--rm", "--network", EGRESS_NET,
             "-v", f"{PROXY_SRC}:/app/proxy.py:ro",
             "-e", "PROXY_BIND_IP=0.0.0.0", "-e", "EGRESS_ALLOWLIST=",
             "--entrypoint", "python3", img, "/app/proxy.py", timeout=120)
    assert out.returncode != 0, "proxy started with an empty allowlist"
    assert "fail closed" in (out.stdout + out.stderr)
