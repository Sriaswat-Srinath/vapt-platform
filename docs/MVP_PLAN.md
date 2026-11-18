# Stakeholder-facing MVP — implementation plan

Baseline: `8f032e9` (M1 lab accepted; M1.5 provisionally accepted, 91/91 probes).
Scope authority: `MVP_SCOPE.md`. Safety authority: `SAFETY.md`, `SECURITY_ASSUMPTIONS.md`,
ADR-0001…0012. **No security invariant is weakened to save time.**

## 0. Reuse inventory (what exists and is kept as-is)

| Asset | State | Reused for |
|---|---|---|
| `docker-compose.lab.yml` (project `vapt-lab`) | M1, accepted | the demonstration target; untouched |
| ZAP daemon, digest-pinned, api-addrs allowlist, `restart: "no"` | M1 | phase 4 scanner execution |
| `scripts/lab_isolation_check.sh` (39 probes) + induced-failure proof | M1 | preflight gate 2 data source (phase 2) |
| `scripts/zap_daemon_state.sh` (R2–R7 reset, D23 acknowledgement) | M1 | phase 4 daemon lifecycle; moves into the API in M5 |
| `docker-compose.yml` four-network topology | M1.5 | the whole application plane |
| `lab/egress-proxy/proxy.py` + adversarial suite | M1.5 + this phase | the only LLM egress path (phase 5) |
| `scripts/net_verify.sh` (108 probes) | M1.5 + this phase | regression gate for every later phase |
| `backend/tests/invariants/` + manifest | M0 | I1–I14 become implemented as their phases land |
| `lab/seed/MOCK-WEB-001.json` | M1 | asset + scope-rule seed (phase 2) |

Nothing in M1/M1.5 is rebuilt. Placeholders are replaced, not redesigned.

## 1. Phases, dependencies, acceptance

| Phase | Deliverable | Depends on | Acceptance |
|---|---|---|---|
| **1. Real datastores** ✅ **done** | digest-pinned PostgreSQL 16.6 + Redis 7.4.1, core-only, scram-sha-256, `requirepass`, interface-bound | M1.5 | `net_verify` **108/108** incl. `NET-P1…P11`; no egress path; boundaries unchanged (M2-N1, M2-N6) |
| **2. Backend core** | FastAPI (config, structured logs, trace ids, RFC 9457), Alembic baseline, Argon2 token auth + analyst/approver/admin, assets, scope rules, scope grants with the `document_state` CHECK, approvals, operator identities, **the full preflight gate chain**, audit hash chain, `/system/*` | 1 | `tests/safety/` matrix green; invariants **I1, I2, I3, I9, I14** implemented; registering an external target is **rejected**; `/audit/verify` passes; api keeps edge-only bind (`NET-G5`, `NET-J8` green) |
| **3. Jobs + discovery** | Celery worker on `vapt_core`+`vapt_lab`, job lifecycle (queued→…→terminal), cancellation within SLA, crawler, attack-surface inventory, deterministic surface→candidate-test matrix | 2 | job state machine tests; cancellation ≤ `CANCELLATION_SLA_SECONDS`; inventory stable across two runs; worker airgap re-verified (`NET-G*`) |
| **4. ZAP execution** | `ScannerAdapter` protocol, `mock` adapter (default), `zap` adapter, global daemon lease, per-job contexts, verification-gated reset, raw observations | 3 | passive baseline job completes against Juice Shop; invariants **I8, I13**; cross-job contamination test; **flags stay `false` until phase 8 explicitly enables passive execution** |
| **5. Findings + evidence + AI** | normalisation, fingerprint/dedup, evidence blobs + references + pinning, deterministic validation rules, CVSS from catalogue, redaction boundary, bounded LangGraph agent, test-selection proposals | 4 | invariants **I5, I6, I7, I11, I12**; a seeded false positive is **not** confirmed; every agent claim cited; agent cannot change status |
| **6. Dashboard** | React/TS/Vite, six screens, generated OpenAPI types, react-query | 2 (usable), 5 (complete) | component tests; scope denials rendered with their ordered gate reasons; evidence rendered as escaped text |
| **7. Reports** | HTML + PDF + JSON, limitations section generated from coverage | 5 | invariant **I10**; report names `MOCK-WEB-001` as synthetic; regeneration deterministic |
| **8. Demonstration + hardening** | end-to-end run, regression, operator runbook | all | the full workflow below, plus the rejection case |

## 2. The demonstration (phase 8 acceptance)

1. Analyst logs in. 2. Selects `MOCK-WEB-001`. 3. **Registering an external target is rejected**
with the ordered gate reasons. 4. Initiates a permitted **passive/baseline** assessment.
5. Discovery produces the attack-surface inventory. 6. Candidate tests derive from the surface.
7. ZAP executes the permitted profile. 8. Evidence is collected. 9. Deterministic validation
classifies findings. 10. The agent explains impact and remediation from **redacted** evidence.
11. An HTML/PDF report is generated, stating its limitations.

Active/intrusive testing stays disabled: it requires `ACTIVE_SCAN_ENABLED` **and** genuine dual
control (ADR-0009). The guaranteed demo is passive; the agent *proposing* an injection test and the
gate **denying** it with reasons is itself part of the demonstration.

## 3. Conditions carried from the M1.5 review

| ID | Requirement | Where enforced |
|---|---|---|
| M2-N1 | real PostgreSQL/Redis introduce no egress path | `NET-P1…P6`, `NET-F:*` — **met in phase 1** |
| M2-N2 | api retains internal-only connectivity | `NET-H1`, `NET-F:api` |
| M2-N3 | worker gains no direct internet access | `NET-G1`…`NET-G7` |
| M2-N4 | proxy ACL independently verified | `tests/net/test_proxy_adversarial.py` (37 cases) |
| M2-N5 | lab resets never delete application-plane resources | separate compose projects + 2 regression tests |
| M2-N6 | re-run network verification after replacing placeholders | `net_verify` is acceptance for every phase |
| M2-N7 | scanner execution flags stay disabled until separately authorised | `SCANNER_EXECUTION_ENABLED=false` asserted in each phase report |

Also carried: **the stand-in tests are not evidence of production LLM security.** The stand-in is
plain TCP; TLS, certificate validation and provider behaviour are untested and are called out
separately in phase 5.

## 4. Rules for every phase
Tests · security-boundary verification (`net_verify` + `lab-check` + invariants) · regression ·
documentation · an acceptance report. Simulated functionality is never reported as implemented.

## 5. RESOLVED (phase 8) — host hygiene and the scan gate

> **Decision, 2026-11-18:** gate 2 requires BOTH `isolation_passed` and
> `host_hygiene_passed`, kept as separate verdicts so a denial names which half failed.
> A `null` hygiene verdict is a denial. Recorded in
> [ADR-0015](adr/ADR-0015-gate2-requires-host-hygiene.md); the gate was not weakened to make
> preflight pass. The original question is kept below for context.

## 5a. The original open question — host hygiene and the scan gate

`PUB-2` found a host listener on `0.0.0.0:5433` belonging to **`corelayer-lab-db`, an unrelated
project on this machine**. Lab containers can reach it through the lab gateway (D20/B10). It is not
ours to remove.

Previously `PUB-2` hard-failed the lab verdict, which conflated two different things and cascaded
into recovery (`make lab-zap-restart` runs the check). The check now reports three verdicts:

| Verdict | Meaning |
|---|---|
| `isolation_passed` | **containment** — container→internet and container→LAN blocked. The control. |
| `host_hygiene_passed` | no foreign `0.0.0.0` host listeners reachable from the lab. Operator hygiene. |
| `access_passed` | the optional workstation forwarder works. |

`passed` still requires **all three**, so `make lab-check` fails loudly while the foreign listener
exists. `make lab-check-containment` (and the recovery path) require containment only. `PUB-1` — no
*VAPT* container publishes on `0.0.0.0` — remains fatal.

**Decision needed:** should preflight gate 2 consume `host_hygiene_passed` as well as
`isolation_passed`? Blocking is stricter but makes any unrelated local service stop all scanning;
warning keeps scanning available while recording the exposure in the `ScopeDecision` and the report.
My recommendation: **record it in the decision and surface it prominently, do not block**, because
containment is the property that bounds the scanner, and the hygiene finding is outside the
platform's control. I have not changed gate 2 — it does not exist yet (phase 2).
