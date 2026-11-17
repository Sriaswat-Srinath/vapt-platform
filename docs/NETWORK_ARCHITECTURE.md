# Network Architecture — M1 → M2

Status: **measured in M1.5 (2026-11-17).** Every row below was verified by `scripts/net_verify.sh`
against running placeholder containers — 91 probes, all passing — not assumed. Evidence:
`docs/evidence/m1_5/`. Probe ids live in the `NET-*` namespace (see `INVARIANTS.md` §0).

## 1. Reachability classes — the vocabulary this document uses

Measured on the M1 lab (Docker 29.1.3, `internal: true` bridge). These are different things and are
never conflated:

| Class | Lab result | Mechanism |
|---|---|---|
| **container → internet** | `ENETUNREACH` — blocked | no default route; iptables isolation of forwarded traffic |
| **container → LAN** (incl. the LAN gateway) | `ENETUNREACH` — blocked | same |
| **container → host via host's LAN IP / `docker0`** | `ENETUNREACH` — blocked | no route |
| **container → host via the lab gateway `172.30.10.1`** | **reachable** for any host service bound on `0.0.0.0` (`ECONNREFUSED` when nothing listens) | the host owns the bridge; this is local delivery, not forwarding |
| **container → container, same network** | reachable | normal |
| **container → container, other Docker network** | blocked | no route |
| **host → container** | **reachable** on the container's IP | host-local routing |
| **LAN peer → container** | not reachable without host routing | no published 0.0.0.0 port; `ip_forward=1` on this host is noted — a route on the LAN would be required |

Measured again in M1.5 for the application plane (`api`, `worker`, `frontend` placeholders), probes
`NET-HG:*`, `NET-G*`, `NET-H*`, `NET-I*`:

| Source | → internet | → LAN gw | → host via **its network gateway** | → host via host **LAN IP** |
|---|---|---|---|---|
| `api` | `ENETUNREACH` | `ENETUNREACH` | `ECONNREFUSED` (L3 reachable, nothing listening) | `ENETUNREACH` |
| `worker` | `ENETUNREACH` | `ENETUNREACH` | `ECONNREFUSED` (L3 reachable) | `ENETUNREACH` |
| `frontend` | `ENETUNREACH` | `ENETUNREACH` | `ECONNREFUSED` (L3 reachable) | `ENETUNREACH` |
| `egress-proxy` | reachable (**by design** — it is the boundary) | — | — | — |

`net.ipv4.ip_forward` on this host is **`1`**, recorded in every result. A LAN peer still needs a
route to a VAPT subnet, and no VAPT container publishes on `0.0.0.0` (`PUB-1`), but the setting is
reported rather than relied upon.

**One mechanism distinction, found by measurement.** For the proxy — the only container that *must*
have a default route — packets addressed to an internal VAPT subnet do not fail with `ENETUNREACH`.
They leave via the default route, reach the host (which does have routes to those bridges, with
`ip_forward=1`), and are then **silently dropped by Docker's inter-network isolation rules**, so the
observed class is a timeout. The destination is unreachable either way, but the guarantee rests on
iptables rather than on the absence of a route. Probes `NET-J7*`/`NET-J9*` therefore accept
`ENETUNREACH | TIMEOUT` and say so in their detail text. Every other component has **no default
route at all** (`NET-F:*`), which is the stronger property.

**`internal: true` is container-to-internet and container-to-LAN isolation. It is not host
isolation in either direction.** Two consequences are already enforced in M1 and become standing
rules: every host publish binds `127.0.0.1` (probe `I14`), and the lab gateway IP is never a valid
scan target (scope gates 8–10; the forwarder refuses it).

## 2. Networks

| Network | `internal` | Subnet | Members | Purpose |
|---|---|---|---|---|
| `vapt_edge` | **yes** | `172.30.20.0/24` | `frontend`, `api` | analyst-facing plane; **the api's HTTP listener binds here only** |
| `vapt_core` | **yes** | `172.30.21.0/24` | `api`, `worker`, `postgres`, `redis` | application plane |
| `vapt_egress` | **yes** | `172.30.22.0/24` | `api`, `egress-proxy` | the api's only path outward |
| `vapt_wan` | **no** | `172.30.23.0/24` | `egress-proxy` (+ the M1.5 test stand-in) | **the only network with a route off-host** |
| `vapt_lab` | **yes** | `172.30.10.0/24` | `worker` (from M3), `zap`, `juiceshop` | target plane |

This supersedes the earlier `enable_ip_masquerade=false` proposal: the api sits on **internal
networks only**, so it has no route to the internet at all, and the proxy is dual-homed
`vapt_egress` + `vapt_wan`. Nothing depends on masquerade semantics, and the M2 risk item about
measuring them is **retired**. Verified: `NET-A:*` (exact attachment sets), `NET-F:*` (only the proxy
has a default route), `NET-H1` (api → internet `ENETUNREACH`).

## 3. Per-component access

| Component | Networks | May initiate to | Must never reach | Host publish |
|---|---|---|---|---|
| **Frontend** (nginx, static) | `vapt_edge` | `api` only (same-origin reverse proxy path `/api`) | postgres, redis, worker, lab, internet | `127.0.0.1:5173` (dev) / `127.0.0.1:8443` |
| **FastAPI** | `vapt_edge`, `vapt_core` | `postgres`, `redis`, **`egress-proxy` only** for the LLM | lab network, ZAP, Juice Shop, any internet host directly | `127.0.0.1:8000` |
| **PostgreSQL** | `vapt_core` | nothing (server only) | everything | none |
| **Redis** | `vapt_core` | nothing (server only) | everything | none |
| **Scanner worker** | `vapt_core`, `vapt_lab` | `postgres`, `redis`, `zap`, the **pinned target IP** only | api, frontend, egress-proxy, internet, LAN, lab gateway | none |
| **ZAP** | `vapt_lab` | the pinned target only (context include/exclude) | everything else | **none** (API via `api.addrs` allowlist + key, worker range only) |
| **Juice Shop** | `vapt_lab` | nothing (it is the target) | everything | none; D19 forwarder is host-side and opt-in |
| **LLM provider** | external | — | — | reached **only** through `egress-proxy` |
| **egress-proxy** | `vapt_edge` | the **one configured provider host:443** | everything else | none |

## 4. The API egress boundary

Requirement: the LLM integration must not become an unrestricted network proxy, and the worker must
not gain internet access directly or indirectly.

### 4.1 Network layer — an allowlisting egress proxy
`api` has **no route to the internet** (it is on internal networks only; `NET-H1`). Outbound traffic
exists solely as `CONNECT` through `egress-proxy` (`HTTPS_PROXY=http://172.30.22.60:3128`, asserted
by `NET-C:api-proxy`). The proxy (`lab/egress-proxy/proxy.py`, digest-pinned base image, non-root,
read-only rootfs, `cap_drop: ALL`) enforces:

- **`CONNECT` only** — any other method is refused `403` (`NET-J4a/b`: plain-HTTP absolute-URI `GET`
  and `POST` both denied, logged as `method_not_connect`);
- destination must match `EGRESS_ALLOWLIST` **exactly** as `host:port`, no wildcards or suffixes
  (`NET-J1` permitted; `NET-J2` same host wrong port, `NET-J3` wrong host, `NET-J5` internal
  component, `NET-J6` scanner plane — all `403 destination_not_allowlisted`);
- the resolved address must not fall inside an internal VAPT subnet, so an allowlisted **name**
  cannot be pointed at an internal component;
- it binds **one interface** (its `vapt_egress` address), so the WAN side cannot use it as a proxy
  (`NET-J11`);
- it refuses to start with an empty allowlist (fail closed);
- no caching, no body handling, no credential passthrough; one JSON decision line per request
  (`verdict`, destination, resolved addresses, bytes, trace id) — `NET-J10`/`NET-J10b`, shipped into
  the audit trail in M2.

Measured in M1.5: 80 decisions — 16 allow, 16 close, **48 deny** (32 `destination_not_allowlisted`,
16 `method_not_connect`); the only destination ever permitted was `llm-standin:8443`
(`docs/evidence/m1_5/proxy-decision-summary.txt`).

The proxy is **the** egress boundary: an application bug cannot open a destination it does not allow.

### 4.1a Test-only stand-in configuration (M1.5)

| Setting | M1.5 value | Production value |
|---|---|---|
| `LLM_PROVIDER_HOST` | `llm-standin` (container on `vapt_wan`) | the one configured provider host |
| `LLM_PROVIDER_PORT` | `8443` (unprivileged; the stand-in runs non-root) | `443` |
| `EGRESS_ALLOWLIST` | `llm-standin:8443` only | `<provider>:443` only |

The proxy never terminates TLS — it only tunnels — so `CONNECT` semantics are identical with or
without TLS; the tunnel is proven by end-to-end bytes (`PING` → `PONG`, `NET-J1b`). **The real
provider is never contacted**, and that is asserted rather than intended: `NET-K2` fails if the test
allowlist names anything but the stand-in, `NET-K3` fails if the decision log contains a permitted
tunnel to any other destination, and `NET-K4` requires every permitted tunnel to have resolved to
`172.30.23.70`. `LLM_ENABLED=false` throughout and no provider credential exists in any container's
environment (`NET-C:api-nocred`, `NET-C:worker`, `NET-C:frontend`).

### 4.2 Application layer — no SSRF surface
- The LLM client (`agent/llm/provider.py`) takes no URL from any caller; base URL is config-only.
- No endpoint fetches a user-supplied URL in the MVP: no webhooks, no "import from URL", no remote
  report assets. WeasyPrint runs with a `url_fetcher` that **refuses every network URL**.
- Agent tools cannot issue HTTP requests (ADR-0007/0010; import-linter forbids `httpx` in `agent/`).
- Prompts are sent to the provider through the typed `PromptEnvelope[RedactedText]` path only.

### 4.3 The worker is airgapped — directly and indirectly (**measured**)
- Networks: `vapt_core` only in M1.5; `vapt_lab` is added in M3. Both internal. No proxy variables,
  no provider credentials, no API token (`NET-A:worker`, `NET-C:worker`, `NET-F:worker`).
- Measured from inside the worker container: internet `ENETUNREACH` (`NET-G1`), LAN gateway
  `ENETUNREACH` (`NET-G2`), **`egress-proxy:3128` `ENETUNREACH`** (`NET-G3`), api edge address
  `ENETUNREACH` (`NET-G4`), api core address **`ECONNREFUSED`** (`NET-G5` — see §5), the WAN
  stand-in `ENETUNREACH` (`NET-G7`). Postgres and Redis are reachable, as they must be
  (`NET-G6a/b`).
- **Indirect paths closed:** the worker cannot reach the proxy at all; the API exposes no endpoint
  that performs outbound requests on a caller's behalf, and the worker cannot reach the API anyway;
  Redis and Postgres carry data, not connections. A compromised worker can cause no outbound request
  other than the LLM calls the API itself decides to make, which carry only redacted, typed content.
- Induced-failure proof: attaching the worker to `vapt_wan` makes 8 probes fail — including
  `NET-G1` (internet **REACHABLE**) and `NET-G2` (LAN gateway **REACHABLE**) — and detaching restores
  them (`docs/evidence/m1_5/net-evidence-2-induced-failure.json`).

## 5. Host publishing and interface binding (from D19/D20, measured in M1.5)
- Every published port binds **`127.0.0.1`** — probe `I14` fails on any `0.0.0.0` publish of a
  VAPT container, and `I14b` reports host-wide `0.0.0.0` listeners because lab containers can reach
  them via the gateway.
- `api` and `worker` share `vapt_core` (both need Postgres and Redis), so network membership alone
  would let the worker call the API. Therefore `api` binds **only its `vapt_edge` interface**
  (uvicorn `--host` resolved to the edge address at start-up), so nothing on `vapt_core` can reach
  it, and the API additionally exposes no endpoint that performs outbound requests on a caller's
  behalf. Both are tested in M2; the fallback if single-interface binding proves unreliable is a
  split `vapt_core` (api↔db and worker↔db on separate internal networks).

## 6. M2 verification additions
Worker → internet / LAN / proxy / api: all unreachable · api → internet direct: `ENETUNREACH`; api →
provider via proxy: allowed; api → any other host via proxy: `403` and logged · frontend → postgres /
redis / lab: unreachable · all publishes loopback-only · egress-proxy ACL denies non-provider hosts,
non-443 ports and plain HTTP · WeasyPrint network fetch refused · worker holds no `HTTPS_PROXY`, no
LLM env.
