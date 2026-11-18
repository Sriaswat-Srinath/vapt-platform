# MVP Phase 1 — Real datastores + proxy security review

Baseline `8f032e9`. **Infrastructure and verification only. No application code exists yet**
(`backend/app/` does not exist). No scan performed; flags `false`; authorisation unsigned.

## 1. Addressing the M1.5 review conditions

### Critical 1 — the proxy is a security boundary (your checklist, item by item)

| Your check | Finding | Action |
|---|---|---|
| validates the hostname **before** connecting | already correct — allowlist precedes resolution | — |
| resolves hostnames itself | already correct (`getaddrinfo`, A records) | — |
| **connects to the validated IP** | already correct: `create_connection((validated_addr, port))`. There is no second resolution, so **no DNS-rebinding window between check and connect** | documented explicitly |
| IPv4/IPv6/alternative representations | ⚠ IPv6 handling implicit; decimal (`2130706433`) and hex (`0x7f000001`) forms were caught only by the allowlist | now **explicitly refused** as `ambiguous_numeric_host`; IPv6 literals refused as `malformed_host`; A-records only, documented |
| alternative CONNECT syntax | sound, but denial reasons were coarse | strict target validator: scheme, userinfo, path, brackets, embedded colons, whitespace, trailing dot, leading-zero port each get their own refusal reason |
| malformed requests rejected safely | correct | plus HTTP-version check, header-line cap, control-character scrubbing in logs |
| **connection limits and timeouts** | ✘ **real gap: unbounded threads, no concurrency cap, no tunnel duration/byte cap** | bounded semaphore (`503 capacity_exceeded`), `MAX_TUNNEL_SECONDS`, `MAX_TUNNEL_BYTES`, header timeout, idle timeout — all declared in the startup log |

Two further hardenings I added beyond the checklist:

- **Source enforcement inside the proxy** (`ALLOWED_CLIENT_CIDRS`, default the api's egress address
  only). Network isolation already stops the worker and frontend; the proxy now refuses them too, so
  the control does not rest solely on network state.
- **Resolved-address class check**: an allowlisted *name* that resolves to loopback, link-local or
  any other non-permitted private address is refused (`resolved_address_not_permitted`), in addition
  to the internal-CIDR refusal.

**Adversarial suite: `tests/net/test_proxy_adversarial.py`, 37 cases, all passing.** Highlights:
16 hostile target forms refused by the pure policy function; 12 live refusals over the wire;
`connected_to` in the decision log proves the dialled address equals the validated one; a
non-allowlisted **source** on `vapt_egress` gets `403 source_not_allowed`; a throwaway proxy whose
allowlist deliberately names an **internal** service refuses it with `resolves_into_internal_network`
(proving the address check is independent of the allowlist); 40 simultaneous connections produce
refusals and the proxy keeps serving; an empty allowlist refuses to start.

### Critical 2 — host isolation is not established
Unchanged and still disclosed. `ECONNREFUSED` from a container to its gateway is recorded as
*L3-reachable, nothing listening* — never as isolation. No document claims complete host isolation.

### Critical 3 — the proxy's WAN access is a trust concentration
Accepted as a real concentration. Reduced this phase by: source allowlist, capacity/duration/byte
limits, single-interface bind, A-records-only resolution, address-class checks, and an independently
tested ACL. Not eliminated — recorded as the residual it is.

### High — DNS and alternative protocols (new probes)
`NET-DNS:{api,worker,frontend}` → **UNRESOLVED**: a public name does not resolve from any
application container, so DNS cannot be used as an egress channel. `NET-UDP:{api,worker}` → UDP/53
to a public resolver gets **no reply**. The proxy *does* resolve, by design — it is the boundary, and
its ACL is the control (`NET-DNS:proxy`).

## 2. Real datastores (your first implementation priority)

| | |
|---|---|
| PostgreSQL | `postgres@sha256:1d04b9ba…` (16.6-alpine3.21), uid 70, `cap_drop ALL` + 5 named caps, `scram-sha-256`, `listen_addresses=172.30.21.40` (core interface only), named volume, `log_connections` |
| Redis | `redis@sha256:c1e88455…` (7.4.1-alpine3.20), uid 999, **read-only rootfs**, `cap_drop ALL`, `--bind 172.30.21.50`, `--requirepass`, no persistence, `maxmemory 256mb` |

**Boundaries intact — `net_verify` 108/108** (up from 91; 17 new probes). New `NET-P*`:

| Probe | Result |
|---|---|
| `NET-P1`/`P2` postgres/redis → internet | BLOCKED |
| `NET-P3`/`P4` → LAN gateway | BLOCKED |
| `NET-P5`/`P6` → egress proxy | BLOCKED |
| `NET-P7`/`P8` listeners bound to the core interface, not `0.0.0.0` | 0 wildcard binds |
| `NET-P9` `password_encryption` | `scram-sha-256` (authenticated query) |
| `NET-P10` redis rejects unauthenticated commands | `NOAUTH` |
| `NET-P11` `pg_hba.conf` trust lines | 0 |
| `NET-F:postgres`/`NET-F:redis` default route | NONE |

Induced failure re-proven: attaching the worker to `vapt_wan` now fails **10** probes (the new
`NET-DNS:worker` and `NET-UDP:worker` catch it too); reverting restores 108/108.

## 3. Test results (full pass, in one run, lab and app plane both up)

| Suite | Result |
|---|---|
| `net_verify.sh` | **108/108, exit 0** — and exit 0 again after the lab suite ran `lab-reset` |
| `lab_isolation_check.sh --require containment` | **exit 0** (39 probes) |
| `pytest tests/net` (architecture + adversarial) | **56 passed** |
| `pytest tests/lab` | **62 passed** |
| `pytest backend/tests/invariants` | **11 passed, 13 milestone-aware skips preserved** |

**Failed tests at completion: none.**

## 4. Defects found and fixed this phase

| Defect | Fix |
|---|---|
| Probe helpers assumed `python3` in every container; the real postgres/redis images have none, so `NET-F` errored — and a `nc`-based probe would have **silently passed if `nc` were missing** (the M1 `ip route` false-pass class) | capability-detected helpers (`have`, `route_of`, `tcp_coarse`, `dns_of`); a missing tool yields `NO_PROBE_TOOL`, which **fails** |
| A probe error containing `\r` produced invalid JSON | `add()` strips all control characters; malformed results still fail loudly *and* emit valid JSON |
| `psql`/`grep -c` probe mechanics (auth required; exit 1 on zero matches) | authenticated query over the core interface; `awk` counting with an explicit unreadable-file case |
| `PUB-2` hard-failed the lab verdict because of **an unrelated project's** `0.0.0.0:5433` listener, cascading into two recovery tests via `lab-zap-restart` | three distinct verdicts (`isolation_passed`, `host_hygiene_passed`, `access_passed`); `passed` still requires all three; recovery uses `--require containment`; `PUB-1` stays fatal. **Open question for you in `MVP_PLAN.md` §5** |

## 5. Limitations (unchanged honesty)

1. **No application code exists.** `api`, `worker` and `frontend` are still placeholder listeners.
   Phase 1 proves infrastructure, not behaviour.
2. The datastores are real but **unused**: no schema, no migrations, no data. Postgres holds an empty
   initialised cluster.
3. The stand-in remains plain TCP. **TLS, certificate validation and provider behaviour are
   untested** — the stand-in tests are not evidence of production LLM integration security.
4. The proxy is purpose-built (~210 lines). Now adversarially tested, but it is not a hardened
   general proxy; swapping in Squid remains an option in phase 5.
5. B11 stands: the proxy's internal-subnet unreachability rests on Docker isolation rules.
6. Host hygiene fails while a foreign `0.0.0.0` listener exists on this machine (yours, not ours).
7. Scanner execution, active scanning and dual control remain **disabled**; the authorisation
   document is untouched and unsigned; no `ScopeGrant` exists.

**Next: phase 2 — backend core (FastAPI, Alembic, auth, assets, scope, the full preflight gate
chain, audit chain). Not started.**
