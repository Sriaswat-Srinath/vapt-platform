# M1.5 — Network architecture corrections and verification

**Not started. Awaiting approval.** Infrastructure and tests only; no application endpoints.

## Purpose
Prove the M2 topology (`NETWORK_ARCHITECTURE.md`) on this host **before** application code depends on
it — the same discipline as M1: measure, don't assume.

## Deliverables
| # | Item |
|---|---|
| 1 | `docker-compose.yml`: `vapt_edge`, `vapt_core`, `vapt_egress`; **placeholder** containers for `api`, `worker`, `frontend` (minimal images that only expose a health port and a probe shell), `postgres`, `redis`, `egress-proxy` (digest-pinned, non-root, read-only, `CONNECT`-only ACL to `LLM_PROVIDER_HOST:443`) |
| 2 | Measurement of `enable_ip_masquerade=false` for the api network; fallback topology applied if it does not hold |
| 3 | `scripts/net_verify.sh` + `tests/net/`: worker→internet/LAN/proxy/api unreachable; api→internet direct `ENETUNREACH`; api→provider via proxy `CONNECT` allowed (to a stand-in host in the lab job; real provider not contacted); api→other host via proxy denied+logged; frontend→postgres/redis/lab unreachable; all publishes loopback (`I14`); no container has the Docker socket; proxy ACL denies non-443, plain HTTP, non-allowlisted hosts |
| 4 | Induced-failure case: attach `worker` to `vapt_egress` ⇒ `net_verify` **fails**; revert ⇒ passes |
| 5 | `NETWORK_ARCHITECTURE.md` updated with measured results; `CONFIGURATION.md` gains `LLM_PROVIDER_HOST`, proxy settings |

## Acceptance
All tests in (3) pass; (4) proven in both directions; no LLM provider contacted; no scan; flags
unchanged; authorisation document unchanged.

## Out of scope
Any FastAPI route, migration, auth, or worker task. Those are M2.
