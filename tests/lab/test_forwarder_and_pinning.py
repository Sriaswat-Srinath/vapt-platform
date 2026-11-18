"""D19 forwarder conditions and D21 digest pinning — including the NEGATIVE
cases: the forwarder must refuse any destination other than the registered
target, and must not act as a proxy to anywhere else."""
from __future__ import annotations
import http.client, json, os, pathlib, re, subprocess, pytest

REPO = pathlib.Path(__file__).parents[2]
FWD = REPO / "scripts" / "lab_publish.py"


def run_fwd(env_extra: dict, *args: str):
    env = {**os.environ, **env_extra}
    return subprocess.run([str(FWD), *args], cwd=REPO, capture_output=True, text=True, timeout=20, env=env)


# ---- D19 negative: no arbitrary destination -----------------------------------
@pytest.mark.parametrize("env,args,why", [
    ({}, ("--target-host", "1.1.1.1"), "CLI destination override"),
    ({}, ("93.184.216.34", "80"), "positional destination"),
    ({"JUICESHOP_IP": "93.184.216.34"}, (), "public IP via env"),
    ({"JUICESHOP_IP": "192.168.1.1"}, (), "LAN gateway via env"),
    ({"JUICESHOP_IP": "172.30.10.1"}, (), "lab gateway (the host) via env"),
    ({"JUICESHOP_IP": "172.18.0.2"}, (), "another docker network via env"),
    ({"JUICESHOP_IP": "example.com"}, (), "hostname via env"),
    ({"JUICESHOP_IP": "127.0.0.1"}, (), "loopback via env"),
])
def test_forwarder_refuses_unrelated_destination(env, args, why):
    r = run_fwd(env, *args)
    assert r.returncode != 0, f"{why}: forwarder started against an unrelated destination"
    assert "refused" in (r.stdout + r.stderr).lower(), f"{why}: {r.stdout}{r.stderr}"


def test_forwarder_listen_host_is_a_literal_loopback():
    src = FWD.read_text()
    assert re.search(r'LISTEN_HOST\s*=\s*"127\.0\.0\.1"', src)
    assert "0.0.0.0" not in src.replace("bound on 0.0.0.0", "")  # no wildcard bind anywhere


def test_forwarder_is_not_started_automatically():
    mk = (REPO / "Makefile").read_text()
    for target in ("lab-up:", "lab-reset:"):
        body = mk.split(target, 1)[1].split("\n\n", 1)[0]
        assert "lab_publish" not in body and "lab-publish" not in body, f"{target} starts the forwarder"
    for f in REPO.glob("tests/**/*.py"):
        assert "lab-publish" not in f.read_text() or f.name == pathlib.Path(__file__).name
    assert "lab-down: lab-unpublish" in mk  # explicit shutdown path


def _forwarder_up() -> bool:
    pid = REPO / ".lab-state" / "publish.pid"
    if not pid.exists():
        return False
    try:
        os.kill(int(pid.read_text()), 0)
        return True
    except (ProcessLookupError, ValueError):
        return False


@pytest.mark.skipif(not _forwarder_up(), reason="forwarder not running (opt-in: make lab-publish)")
def test_forwarder_cannot_be_used_as_a_proxy():
    """CONNECT and absolute-URI requests through 127.0.0.1:3000 must land on
    Juice Shop (and be answered by it), never be relayed to the named host."""
    c = http.client.HTTPConnection("127.0.0.1", 3000, timeout=10)
    c.request("CONNECT", "example.com:443")
    try:
        r = c.getresponse(); r.read(400)
        assert r.status != 200, "CONNECT tunnel was granted — forwarder is proxying"
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass  # the target closed the connection: no tunnel, which is the point
    finally:
        c.close()
    c = http.client.HTTPConnection("127.0.0.1", 3000, timeout=10)
    c.request("GET", "http://example.com/", headers={"Host": "example.com"})
    r = c.getresponse(); body = r.read(4000).decode("utf-8", "replace")
    assert "Example Domain" not in body, "absolute-URI request was relayed to the internet"
    # The response is from Juice Shop itself (express/angular app), not a proxy.
    assert r.status in (200, 404, 400, 500)
    c.close()
    # And the only outbound socket the forwarder holds is to the registered target.
    pid = (REPO / ".lab-state" / "publish.pid").read_text().strip()
    out = subprocess.run(["ss", "-tnpH"], capture_output=True, text=True).stdout
    peers = {ln.split()[4].rsplit(":", 1)[0] for ln in out.splitlines() if f"pid={pid}," in ln and "ESTAB" in ln}
    assert peers <= {"172.30.10.20", "127.0.0.1"}, f"forwarder connected elsewhere: {peers}"


# ---- D21: digest pinning + reproducible startup ----------------------------------
def test_lab_images_are_digest_pinned():
    cfg = json.loads(subprocess.run(["docker", "compose", "-f", "docker-compose.lab.yml", "config", "--format", "json"],
                                    cwd=REPO, capture_output=True, text=True).stdout)
    for name, svc in cfg["services"].items():
        assert re.fullmatch(r"[\w./-]+@sha256:[0-9a-f]{64}", svc["image"]), f"{name} is not digest-pinned: {svc['image']}"


def test_running_containers_match_pinned_digests():
    cfg = json.loads(subprocess.run(["docker", "compose", "-f", "docker-compose.lab.yml", "config", "--format", "json"],
                                    cwd=REPO, capture_output=True, text=True).stdout)
    for name, svc in cfg["services"].items():
        want = svc["image"].split("@", 1)[1]
        cname = svc["container_name"]
        digests = subprocess.run(["docker", "inspect", cname, "--format", "{{json .Image}}"],
                                 capture_output=True, text=True).stdout
        img_id = json.loads(digests)
        repo_digests = json.loads(subprocess.run(["docker", "image", "inspect", img_id, "--format", "{{json .RepoDigests}}"],
                                                 capture_output=True, text=True).stdout)
        assert any(d.endswith(want) for d in repo_digests), f"{cname} runs an image other than the pinned digest"
