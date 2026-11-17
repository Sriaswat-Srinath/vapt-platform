# M1.5 — Network architecture corrections and verification

**Approved in principle; the five owner corrections below are incorporated.** Infrastructure and
verification only.

## 0. Boundary (unchanged, asserted by tests)
Placeholder containers only · no application endpoints · no migrations · no authentication
implementation · no ZAP adapter or scanner execution · no discovery or scanning · **no real LLM
calls** · all safety flags `false` · authorisation document unchanged.

## 1. Correction 1 — identifier namespaces (resolves the `I14` collision)

`I14` was used for two unrelated things: security invariant **I14** (*asset identity is immutable*)
and a lab probe added after M1 acceptance (*no `0.0.0.0` publish*). Three namespaces are now distinct
and documented; **no invariant changes meaning and no historical evidence changes**:

| Namespace | Form | Registry | Meaning |
|---|---|---|---|
| Security invariants | `I1`…`I14` | [INVARIANTS.md](INVARIANTS.md) | properties that must hold forever; referenced as "invariant I*n*" |
| M1 lab probes (frozen) | `I1a`…`I13`, `F1`…`F4c` | [M1_ACCEPTANCE.md](M1_ACCEPTANCE.md) §3 | M1 acceptance criteria; ids frozen so `docs/evidence/m1/` stays readable |
| Publishing probes | **`PUB-1`, `PUB-2`** | this plan | renamed from the post-acceptance `I14`/`I14b`; same checks |
| M1.5 network probes | **`NET-*`** | this plan §6 | new |

`PUB-1` = no VAPT container publishes on `0.0.0.0`. `PUB-2` = host-wide `0.0.0.0` listeners are
reported (lab containers can reach them via the lab gateway). The three archived evidence files
contain 37 probes and never contained `I14`, so they are untouched; the rename is recorded in
`M1_REPORT.md` §14.

## 2. Correction 2 — host-gateway reachability for every plane

For **api, worker and frontend** placeholders, and for both lab containers, the check records and
asserts separately:

- container → internet (expect no route)
- container → LAN subnet and LAN gateway (expect no route)
- container → **host via that network's gateway address** (expect *reachable at L3*; `ECONNREFUSED`
  when nothing listens, `REACHABLE` when something is bound on `0.0.0.0`)
- container → host via the host's **LAN IP** (expect no route)
- `net.ipv4.ip_forward` on the host is **recorded in every result** (currently `1`)

The documents state the consequence plainly: **`internal: true` is container→internet and
container→LAN isolation; it is not host isolation in either direction.** No text claims complete host
isolation. A `0.0.0.0` listener on the host is reachable from any container via its gateway — hence
`PUB-1`/`PUB-2` and the operator note (assumption **B10**).

## 3. Correction 3 — stand-in LLM configuration (explicit, test-only)

| Setting | M1.5 test value | Production value |
|---|---|---|
| `LLM_PROVIDER_HOST` | `llm-standin` (container on `vapt_wan`) | the one configured provider host |
| `LLM_PROVIDER_PORT` | `8443` (unprivileged; the stand-in runs non-root) | `443` |
| `EGRESS_ALLOWLIST` | exactly `llm-standin:8443` | exactly `<provider>:443` |

- The stand-in is a plain TCP responder. The proxy **never terminates TLS** — it only tunnels — so
  `CONNECT` semantics are identical with or without TLS; the tunnel is proven by end-to-end bytes
  (`PING` → `PONG`).
- **The real provider is never contacted.** Asserted, not merely intended: `NET-K2` fails if the test
  allowlist contains any name other than `llm-standin`, and `NET-K3` fails if any public hostname
  resolves or any public address is reachable from the proxy's allowlist path. `LLM_ENABLED=false`
  throughout; no provider credential exists in any container's environment (`NET-C*`).

Permitted vs denied, all tested: permitted `CONNECT llm-standin:8443`; denied — a different host, a
different port on the allowlisted host, plain HTTP / absolute-URI `GET`, any other method, and
`CONNECT` to internal components.

## 4. Correction 4 — proxy bypass and abuse

| Property | Probe |
|---|---|
| api has **no** direct egress (no default route; internet unreachable) | `NET-H1`, `NET-F*` |
| worker cannot reach the proxy | `NET-G3` |
| frontend cannot reach the proxy | `NET-I3` |
| proxy cannot reach application components (postgres, redis, worker) | `NET-J7` |
| proxy cannot reach the api's HTTP port (api binds its **edge** interface only, so the egress-side connect is refused) | `NET-J8` |
| proxy cannot reach scanner components (zap, juiceshop) | `NET-J9` |
| proxy refuses non-allowlisted host / port / method and logs the denial | `NET-J2`…`NET-J6`, `NET-J10` |

The proxy is reached **only** by the api, and is the only container with a WAN route.

## 5. Correction 5 — attachment, identity and configuration verification

Measured from the Docker API and from inside the containers, not assumed:

network attachment set per service (exact match) · container id and image id · **image digest pinned
in compose and the running image's digest matching** · routing table per container
(`/proc/net/route`; only the proxy has a default route) · **environment variables** (worker and
frontend carry no `LLM_*`, no `*_API_KEY`, no `HTTPS_PROXY`/`HTTP_PROXY`; proxy carries no application
credentials) · published ports (none, or loopback-only) · **Docker socket absent from every
container** · and the api's HTTP listener bound to its edge address only, **verified from the
worker's perspective** (`NET-G5`: the worker, which shares `vapt_core` with the api, gets
`ECONNREFUSED`/no-listener rather than a connection).

## 6. Topology under test

```
vapt_edge    internal  172.30.20.0/24   frontend .10   api .20   (api's HTTP listener binds here only)
vapt_core    internal  172.30.21.0/24   api .20   worker .30   postgres .40   redis .50
vapt_egress  internal  172.30.22.0/24   api .20   egress-proxy .60
vapt_wan     bridge    172.30.23.0/24   egress-proxy .60   llm-standin .70     <- the ONLY WAN route
```

This replaces the earlier `enable_ip_masquerade=false` proposal: the api sits on **internal networks
only** and therefore has no route to the internet at all, while the proxy is dual-homed
`vapt_egress` + `vapt_wan`. Nothing depends on masquerade semantics, and the M2 risk item about
measuring them is retired. `postgres` and `redis` are **placeholder listeners** in M1.5; M2 swaps in
the real digest-pinned images on the same networks.

## 7. Deliverables
1. `docker-compose.yml` — the four networks and six placeholder services.
2. `lab/egress-proxy/proxy.py` — CONNECT-only allowlisting proxy (exact `host:port` allowlist, JSON
   decision log). Non-root, read-only rootfs, `cap_drop: ALL`.
3. `lab/llm-standin/standin.py` — test-only TCP responder.
4. `lab/placeholders/listen.py` — placeholder listener with explicit bind address.
5. `scripts/net_subnet_check.sh`, `scripts/net_verify.sh` (JSON result), `scripts/prove_net_failure.sh`.
6. `tests/net/test_net_architecture.py` — one assertion per probe.
7. Probe rename `I14`/`I14b` → `PUB-1`/`PUB-2`; docs updated.
8. `CONFIGURATION.md` additions; `NETWORK_ARCHITECTURE.md` updated with measured results.

## 8. Acceptance
Every `NET-*` probe passes · the induced failure (attach `worker` to `vapt_wan`) makes `net_verify`
**fail**, and reverting makes it pass · the M1 lab check still passes with the renamed probes · no
real provider contacted · no scan · flags `false` · authorisation document unchanged · invariant
manifest unchanged in meaning (I1–I14) with its milestone-aware skips preserved.
