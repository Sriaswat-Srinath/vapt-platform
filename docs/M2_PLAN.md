# M2 Implementation Plan — Backend, database, auth, assets, scope **and the gate chain** (ROADMAP v2)

**Not started. Awaiting approval; M1.5 precedes it.** Re-scoped per `MVP_SCOPE.md`: v2 M2 absorbs the
v1 M3 safety controller because M3 (ZAP execution) cannot exist without the gates.

## 0. Added by the re-scope
| Addition | Acceptance |
|---|---|
| `safety/` preflight chain, gates 1–13, pure `ScopeDecision` | the `tests/safety/` matrix (`SAFETY.md` §6, §7.7); property test: total function, no implicit allow |
| scope grants with `document_state` CHECK, approvals with `invalidated`, `operator_identities`, effective dual control computed at startup and at gate 7 | five-case identity matrix (ADR-0009 R2 §9) — **I3**; grant activation refused while unsigned — **I9** |
| `scope_decisions` persistence + audit | denial returns 409 with ordered `gate_results` |
| invariants I1, I2, I3, I9, I14 implemented | manifest flips them to required when M2 lands |
| LLM provider setting only (`LLM_ENABLED=false`); no provider call in M2 | — |

## 1. Scope
In: FastAPI skeleton (config, structured logging, trace ids, RFC 9457 errors), Alembic baseline
(identity, audit chain, assets, scope rules, scope grants **with `document_state` CHECK**,
approvals, operator identities), asset CRUD + scope rules, token auth and roles, `/system/*`
readiness/capabilities/isolation, the compose services `api`, `postgres`, `redis`, `egress-proxy`,
`frontend` placeholder, and the M2 network tests from `NETWORK_ARCHITECTURE.md` §6.

Out: scanning of any kind, worker job execution (skeleton container only, airgap-tested), discovery,
ZAP adapter, agent, LLM calls, reports, grant activation.

## 2. Standing conditions (unchanged)
`SCANNER_EXECUTION_ENABLED=false` · `ACTIVE_SCAN_ENABLED=false` · `DUAL_CONTROL_AVAILABLE=false` ·
`MOCK-WEB-001.md` unsigned and untouched · no ScopeGrant activated · no scan performed · lab evidence
and the 13 milestone-aware skips preserved; invariants **I9** and **I14** become implemented (their
milestone is M2) and the manifest flips them from skipped to required.

## 3. Deliverables and acceptance
| # | Deliverable | Acceptance |
|---|---|---|
| 1 | `docker-compose.yml` services on `vapt_edge`/`vapt_core`; egress-proxy; all publishes `127.0.0.1` | `I14` passes; worker airgap tests (§6 of the network doc) pass |
| 2 | Alembic baseline + migration tests | up/down clean; CHECKs and triggers asserted by rejection tests |
| 3 | Asset registration | rejects non-`mock_lab`, duplicate host:port, identity updates (trigger) — **I14** |
| 4 | Scope grants | cannot activate unless `document_state='signed_verified'`; startup refuses a tampered active grant — **I9** |
| 5 | Auth + roles | Argon2 tokens, expiry, revocation, per-call audit |
| 6 | Audit chain | `/audit/verify` passes; app role lacks UPDATE/DELETE |
| 7 | `/system/isolation` | reads the M1 check JSON (`isolation_passed`, `valid_until`); stale ⇒ not passed |
| 8 | Fail-fast config | the 16 startup validations from `CONFIGURATION.md` that are testable without scanner code |
| 9 | Tests | unit + integration against real Postgres (testcontainers); invariants I9, I14 implemented |

## 4. Order of work
compose + networks + egress proxy (with tests first) → config + logging + errors → migrations →
auth → assets/scope → grants/approvals/identities → system endpoints → audit verify → invariants.

## 5. Risks specific to M2
- egress-proxy ACL correctness — **retired as a risk**: measured in M1.5 (17 `NET-J*` probes, 48
  logged denials), and the ACL is exercised in both directions.
- `enable_ip_masquerade=false` behaviour — **retired**: the design no longer uses it. The api is on
  internal networks only and has no internet route at all (M1.5 `NET-H1`, `NET-F:api`).
- Single-interface bind — **retired as a risk**: proven in M1.5 from the worker's perspective
  (`NET-G5` `ECONNREFUSED`) and from the proxy's (`NET-J8`). M2 must configure uvicorn's `--host` to
  the resolved `vapt_edge` address and keep `NET-G5` green.
- Remaining: swapping placeholders for the real `postgres:16` / `redis:7` images must preserve every
  `NET-*` property — `net_verify` is re-run as part of M2 acceptance, not just M1.5.
