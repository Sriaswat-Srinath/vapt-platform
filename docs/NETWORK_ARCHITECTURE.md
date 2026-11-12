# Network Architecture — M1 → M2

Status: **proposed for approval before M2.** Builds on the measured M1 facts (D19, D20) rather than
on assumptions about Docker networking.

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

**`internal: true` is container-to-internet and container-to-LAN isolation. It is not host
isolation in either direction.** Two consequences are already enforced in M1 and become standing
rules: every host publish binds `127.0.0.1` (probe `I14`), and the lab gateway IP is never a valid
scan target (scope gates 8–10; the forwarder refuses it).

## 2. Networks

| Network | `internal` | Subnet | Members | Purpose |
|---|---|---|---|---|
| `vapt_edge` | **no** | Docker default | `api`, `frontend`, `egress-proxy` | the only network with a route off-host |
| `vapt_core` | **yes** | Docker default | `api`, `worker`, `postgres`, `redis` | application plane |
| `vapt_lab` | **yes** | `172.30.10.0/24` | `worker`, `zap`, `juiceshop` | target plane |

No other network is created. No service other than `egress-proxy` has an off-host route (§4).

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
`api` does **not** get a route to the internet. It sits on `vapt_edge` with the egress-proxy, and
**outbound HTTPS from `api` is possible only via the proxy** (`HTTPS_PROXY=http://egress-proxy:3128`
plus the api container on an `internal: true`-equivalent posture for everything else — implemented by
putting `api` on `vapt_edge` with `com.docker.network.bridge.enable_ip_masquerade=false` so direct
outbound packets are unroutable, while the proxy sits on a separate masqueraded network). The proxy
(Squid or tinyproxy, digest-pinned, non-root, read-only) enforces:

- `CONNECT` only, to exactly `LLM_PROVIDER_HOST:443` (one host, from configuration, no wildcards);
- every other destination, method, port and plain-HTTP request denied and logged;
- no caching, no request body logging, no authentication passthrough beyond the TLS tunnel;
- access log shipped into the audit trail (host, port, allow/deny, bytes, api trace id header).

The proxy is **the** egress boundary: a bug in the application cannot open a destination the proxy
does not allow.

### 4.2 Application layer — no SSRF surface
- The LLM client (`agent/llm/provider.py`) takes no URL from any caller; base URL is config-only.
- No endpoint fetches a user-supplied URL in the MVP: no webhooks, no "import from URL", no remote
  report assets. WeasyPrint runs with a `url_fetcher` that **refuses every network URL**.
- Agent tools cannot issue HTTP requests (ADR-0007/0010; import-linter forbids `httpx` in `agent/`).
- Prompts are sent to the provider through the typed `PromptEnvelope[RedactedText]` path only.

### 4.3 The worker is airgapped — directly and indirectly
- Networks: `vapt_core` + `vapt_lab`, both internal. No proxy variables, no provider credentials.
- **Indirect paths closed:** the worker holds no API token and the API exposes no endpoint that
  performs outbound requests on a caller's behalf; the worker cannot reach `egress-proxy` (different
  network) and the proxy would refuse it anyway (source ACL: `api` only); Redis/Postgres carry data,
  not connections. A compromised worker can enqueue nothing that causes an outbound request except
  the LLM calls the API itself decides to make, which carry only redacted, typed content.
- Tested in M2: from the worker container, `egress-proxy:3128` is unreachable; direct internet
  `ENETUNREACH`; `api:8000` unreachable (api binds only its edge-facing interface, see §5).

## 5. Host publishing rules (from D19/D20)
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
