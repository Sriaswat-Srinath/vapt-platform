# VAPT local laboratory (M1)

An **isolated, disposable, synthetic** web target plus an OWASP ZAP daemon, on a Docker network with
no route off-host. This milestone proves the environment is safe to develop in. **It does not make
the product operational: no scanning happens here.**

## Standing posture

| | |
|---|---|
| Registered asset | `MOCK-WEB-001` — OWASP Juice Shop, deliberately vulnerable, synthetic, no real data |
| In-lab hostname | `shop.brakes-vapt.test` (Docker network alias; resolvable **only** inside `vapt_lab`) |
| Workstation access | **`http://127.0.0.1:3000`** after `make lab-publish` (opt-in loopback forwarder — see "Why a forwarder" below) |
| ZAP API | `http://172.30.10.10:8080`, reachable **only from inside `vapt_lab`** — the port is deliberately **not published** |
| Scanner execution | **disabled** (`SCANNER_EXECUTION_ENABLED=false`, `ZAP_ADAPTER_ENABLED=false`) |
| Active scanning | **disabled** (`ACTIVE_SCAN_ENABLED=false`, `DUAL_CONTROL_AVAILABLE=false`) |
| Authorisation | `lab/authorisation/MOCK-WEB-001.md` is an **unsigned draft**; no ScopeGrant exists or may be activated |

**A running ZAP container is not permission to scan.** ZAP runs so that its isolation can be proven.

## Quick start

```bash
cp .env.example .env            # then set ZAP_API_KEY (openssl rand -hex 24)
make lab-up                     # subnet-checked, then started, then health-gated
make lab-check                  # the isolation verification suite
make test-lab                   # the same facts as pytest
make test-invariants            # security invariants + manifest
make lab-prove-failure          # prove the check FAILS when isolation breaks, then reverts
make lab-down
```

## Why a forwarder (deviation D19, pending ratification)

Docker **silently ignores `ports:`** for a container attached only to an `internal: true` network: the
binding is recorded in `HostConfig.PortBindings` and then never created (`NetworkSettings.Ports` is
`null`, no `docker-proxy`, nothing listening). Publishing directly would require attaching Juice Shop
to a non-internal network, which gives the target egress — rejected.

`make lab-publish` runs a host-side, loopback-only, inbound-only TCP forwarder
(`scripts/lab_publish.py`) from `127.0.0.1:3000` to the lab target. It grants no container any
capability it lacked: the host already reaches the lab bridge directly (`internal: true` blocks
*forwarded* traffic, not host-local routing). No container is dual-homed. `make lab-unpublish` (also
run by `lab-down`) stops it. The isolation check reports this separately as `access_passed`; the
isolation verdict the future scan gate consumes is `isolation_passed`, which the forwarder can
neither help nor hurt.

## Why `shop.brakes-vapt.test` does not work from your browser

It is a **Docker network alias**, not DNS. It resolves only inside `vapt_lab`, which is exactly the
containment being asserted — `make lab-check` fails if the workstation *can* resolve it. Use
`http://127.0.0.1:3000`. **Do not add an `/etc/hosts` entry.** `.test` is reserved by RFC 6761 and the
name is a local fiction; it is not a Brakes India domain and must never be read as one.

## Network topology

```
vapt_lab  (internal: true, 172.30.10.0/24)   no default route, no egress, no DNS leak
   ├── vapt_zap        172.30.10.10:8080   API, NOT published to the host
   ├── vapt_juiceshop  172.30.10.20:3000   alias shop.brakes-vapt.test
   │                                       published → 127.0.0.1:3000 ONLY
   └── (M2+) worker    172.30.10.3x        dual-homed vapt_core + vapt_lab, no LLM credentials
```

Declared for M2 in `docker-compose.yml`: `vapt_edge` (the only network with egress, for the LLM
provider) and `vapt_core` (`internal: true`).

## Container security

| Control | ZAP | Juice Shop |
|---|---|---|
| user | non-root (`zap`) | non-root (image default) |
| read-only rootfs | **yes** (tmpfs: `/home/zap`, `/tmp`, `/zap/wrk`) | no — the app writes its own SQLite/uploads; it is the disposable target, not the scanner |
| `cap_drop: ALL` | yes | yes |
| `no-new-privileges` | yes | yes |
| pids / memory / cpu limits | 512 / 2g / 2.0 | 256 / 1g / 1.5 |
| host bind mounts | **none** | **none** |
| Docker socket | **never** | **never** |
| published ports | **none** | `127.0.0.1:3000` only |
| restart policy | **`no`** (see below) | `no` |

Three independent controls protect the ZAP API: it is not published; ZAP's own
`api.addrs` allowlist admits only the worker range `172.30.10.3x` (the bridge gateway `.1` — i.e. the
host — is deliberately excluded); and the API key is required. The key is an **additional** control,
never a substitute for network isolation.

## ZAP writable paths under `read_only: true` (D22)

| Path | Needed for | Flags |
|---|---|---|
| `/home/zap` | `.ZAP/` home: config, session DB, add-on state, root CA, Java prefs | tmpfs 512 MiB, `nosuid`, uid 1000, `0770` |
| `/tmp` | JVM temp; **native libraries are mapped from here, so it must be executable** | tmpfs 128 MiB, `nosuid`, **no `noexec`** |
| `/zap/wrk` | ZAP working dir (reports/session exports) | tmpfs 64 MiB, `nosuid`, uid 1000 |

A tmpfs declared with options is root-owned `0755` by default; without explicit `uid/gid/mode` ZAP
cannot create its home directory. `noexec` on `/tmp` was removed because the JVM requires it; the
container remains non-root, `cap_drop: ALL`, `no-new-privileges`, read-only elsewhere, no egress.

## What `internal: true` does and does not isolate (D20)

Containers cannot reach the internet or the LAN (`ENETUNREACH`). The **host** can reach containers,
and containers can reach host services bound on `0.0.0.0` via the lab gateway `172.30.10.1`. So:
never publish anything on `0.0.0.0` (probe `I14`), and keep unrelated host services off `0.0.0.0`
(`I14b` lists them). Full matrix: `docs/SECURITY_ASSUMPTIONS.md` §H.

## Recovery

### ZAP crashed or is unreachable

ZAP runs with **`restart: "no"` on purpose**: a crashed daemon must stay down rather than return with
a fresh, empty, healthy-looking session, which would be indistinguishable from a correctly torn-down
daemon and would corrupt evidence integrity (ADR-0008 R3 §9).

**The platform cannot restart containers.** Docker socket access is prohibited, so no code path can
start, stop or restart ZAP. Recovery is an operator action, from your own shell:

```bash
make lab-zap-restart     # docker compose restart zap, then re-run the isolation check
make zap-reset           # verification-gated: clears the dirty flag ONLY on a full pass
```

### Dirty daemon state

`make zap-state` shows it; `make zap-reset` runs the ADR-0008 R3 §10 sequence (health → identity →
`newSession` → assert stores empty → API probe → new instance marker). **Every step must pass before
the dirty flag clears.** There is no force flag, no override and no automatic expiry. A failure at
health or identity sets `requires_operator_restart`, which means the container restart above is
needed first.

**Identity after a restart (D23).** A restarted daemon has lost its instance marker. The identity
step treats that as *untrusted* unless the restart was operator-authorised: `make lab-zap-restart`
issues an acknowledgement bound to the container id, its start time, a fresh daemon instance UUID, a
nonce, the operator identity and issue/expiry timestamps (TTL 600 s). It is single-use, consumed
atomically by the next `zap-reset`, invalidated on any mismatch or expiry, invalidated if it turns out
not to be needed, and **never clears the dirty flag by itself**. A restart performed any other way (a
crash, a raw `docker restart`) fails identity and keeps the daemon dirty. Every transition is appended
to `.lab-state/zap-daemon-audit.log`.

In M1 this is a script-level reference implementation (`scripts/zap_daemon_state.sh`, state in the
git-ignored `.lab-state/`). The API endpoint `POST /system/scanner/reset` is M5.

### Resetting the lab

`make lab-reset` is scoped to compose project `vapt` (`down -v --remove-orphans`, then up). It will
not touch your other containers, volumes, networks or images, and **the Makefile never runs
`docker … prune`** — asserted by `tests/lab/test_lab_recovery.py`.

## Reading `make lab-check`

| Field | Meaning |
|---|---|
| `isolation_passed` | every `I*` probe passed — **the value the M3 scan gate will consume** |
| `access_passed` | every `F*` probe passed — workstation convenience only |
| `passed` | both |
| `egress_blocked` / `dns_contained` | roll-ups of the egress and DNS probes |

Probes read `/proc/net/route` rather than relying on an `ip` binary, and a probe that errors is
recorded as a **failure**, never as a pass.

## Pinned images

Pinned by **digest**, not tag, so a rebuild cannot silently change what is tested. Recorded in
`docker-compose.lab.yml` and in the M1 report. Updating a digest is a deliberate, reviewed change.

## If isolation cannot be established

Scanner execution stays disabled. That is the designed outcome, not a workaround: `make lab-check`
failing (or being stale beyond `ISOLATION_CHECK_TTL_MINUTES`) denies every scan at preflight gate 2
from M3 onward.
