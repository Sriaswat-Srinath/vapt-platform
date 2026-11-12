# Milestone Plan

Each milestone delivers implementation + tests + docs and ends with the report required by
`CLAUDE.md` rule 15 (files changed, commands run, pass/fail, unresolved risks, next milestone).
Nothing is marked done with a failing or skipped test.

**Gating rule:** `SCANNER_EXECUTION_ENABLED` stays `false` and the adapter stays `mock` until M5
acceptance, which includes a passing lab isolation check.

---

## M0 — Project initialisation and architecture *(this deliverable)*
Docs only: architecture, directory structure, schema, API, agent, scanner interfaces, safety
architecture, dependencies, risks, roadmap, data flow, open decisions.
**Acceptance:** you approve the design and the open decisions in `OPEN_DECISIONS.md`.

## M1 — Local mock website lab
- `docker-compose.lab.yml`: Juice Shop + ZAP on an `internal: true` `lab` network, digest-pinned,
  network alias `shop.brakes-vapt.test`, non-root/read-only/cap-dropped scanner, no docker socket.
- `scripts/lab_isolation_check.sh` + `make lab-up`, `lab-check`, `lab-reset`.
- `lab/seed/MOCK-WEB-001.json`.
**Acceptance:** Juice Shop reachable from the worker by its lab hostname; ZAP responds to its REST
API with the API key; egress probes from both containers fail for public IPs and public DNS;
`shop.brakes-vapt.test` does not resolve outside `lab`; the check writes a passing record and an
induced misconfiguration makes it fail.
**Limitations:** no application yet; check is script-level until M3 wires it to the gate.

## M2 — Backend, database and asset management
- FastAPI skeleton, config, structured logging, trace ids, error model.
- Alembic baseline for identity/audit/assets/scope-rules + the append-only audit chain.
- Asset CRUD, scope rules, OpenAPI, token auth and roles.
**Acceptance:** migrations up/down clean; asset registration rejects non-mock environments and
duplicate host:port; `/system/readiness` reflects real dependency state; audit rows written for every
mutation and `/audit/verify` passes; integration tests against a real Postgres.
**Limitations:** no scanning, no discovery, single-tenant.

## M3 — Scope enforcement and safety controller
- `safety/`: scope policy, target resolver, redirect guard, budgets, ordered preflight chain,
  isolation gate, audit helpers. Scope grants + approvals with dual control. `scope_decisions`
  persistence. Rate limiter / concurrency / timeout primitives. Pause-cancel protocol.
**Acceptance:** the full `tests/safety/` matrix in `SAFETY.md` §6 passes; `POST /scope/validate`
returns the ordered gate results; every denial is persisted and audited; property tests show the
policy is total (no input produces an exception or an implicit allow); import-linter forbids
`agent → safety`.
**Limitations:** gates exist before the things they gate — exercised through the mock adapter.

## M4 — Website discovery
- Rate-limited crawler against pinned IPs, extractors for endpoints/params/forms/headers/API/auth
  entry points, assessment-state classification, inventory upsert, discovery API + export.
**Acceptance:** against Juice Shop, discovery produces a stable inventory across two runs (no
duplicate rows, `verified` promotions recorded); out-of-scope redirects dropped and audited; budget
exhaustion ends the run cleanly with a partial, reportable inventory; cancellation honoured ≤2s;
extractor unit tests on recorded HTML fixtures.
**Limitations:** no JS rendering (SPA routes found only via linked assets/API responses);
unauthenticated only.

## M5 — OWASP ZAP integration
- Adapter protocol + registry + profiles; `mock` adapter with fault injection; ZAP adapter (context,
  policy, spider, passive drain, collect, pause/cancel, teardown); raw observation capture.
- `zap-passive` and `zap-baseline-local` profiles; active scanning still disabled by default.
**Acceptance:** mock adapter drives the whole pipeline in CI with no containers; a passive ZAP job
against Juice Shop completes within budget, stores raw observations with hashes, honours
pause/cancel with confirmed stop, and leaves no ZAP session behind; an alert for an out-of-scope URL
is rejected and audited; enabling execution requires both the flag and a fresh isolation pass.
**Limitations:** no active scan, no auth, daemon-reuse isolation (see D4).

## M6 — Finding normalisation and evidence validation
- Versioned ZAP mapping, normaliser, fingerprint + dedup, evidence capture with redaction,
  validation rule packs, validation state machine, re-validation endpoint, analyst classification
  with justification.
**Acceptance:** golden-file tests map recorded ZAP alerts to expected findings; re-running
normalisation and validation is idempotent; unmapped plugin ids surface rather than vanish; each of
the five validation states is produced by at least one real Juice Shop case; `actor_kind='agent'`
validation writes are rejected at the DB level.
**Limitations:** rule packs cover the categories Juice Shop + ZAP passive actually produce.

## M7 — Risk assessment
- `vuln_catalogue` seed with curated CVSS/CWE/remediation, CVSS parsing/validation, versioned
  priority formula with stored inputs, EPSS/KEV snapshot import, risk summary endpoints.
**Acceptance:** CVSS and priority are separately stored and separately displayed; a `candidate`
finding never outranks an equivalent `confirmed` one; every score reproduces exactly from stored
inputs + formula version; missing CVSS/EPSS/KEV degrade to nulls, never zeros; property tests for
monotonicity.
**Limitations:** no environmental CVSS modifiers in the MVP; asset criticality is manual.

## M8 — LangGraph agent
- Graph, state, budgets, read-only tool catalogue, proposal tools, guard, provider abstraction,
  `fake` provider, SSE streaming, run/tool-call/suggestion persistence.
**Acceptance:** all agent tests run against the fake provider; every forbidden action
(shell, HTTP, scan start, status write, cross-asset read, out-of-scope host in output, uncited claim)
is blocked and recorded; budgets halt runs predictably; an accepted suggestion changes nothing until
a human accepts it, and then only as a human-attributed event.
**Limitations:** single bounded workflow; no multi-agent, no long-term memory.

## M9 — React dashboard
- Overview, Registered Assets, Attack Surface, Scan History, Findings, Finding Detail + Evidence,
  AI Assistant, Report Generation. Generated API types, react-query, loading/error/empty states,
  scope-denial and disabled-scanner messaging surfaced verbatim.
**Acceptance:** component tests for each page with mocked API; the UI never allows a request the
backend would reject without explaining why; evidence rendered safely (no raw HTML injection from
scanner payloads — this is the one place an XSS in our own dashboard is a real risk, so evidence is
rendered as escaped text only); validation/CVSS/priority shown as read-only platform values.
**Limitations:** desktop-first, no RBAC-aware UI beyond hiding approver actions.

## M10 — Reporting
- Assembler, section builders, HTML/PDF/JSON renderers, artifact hashing, download + audit,
  limitations section generated from actual coverage data.
**Acceptance:** a report for a real passive scan contains every mandated section; counts match the
API; the limitations section automatically names passive-only scope, unauthenticated coverage,
budget-exhausted jobs, unmapped detections and inconclusive findings; JSON artifact round-trips;
regeneration is deterministic for the same inputs (byte-identical apart from a timestamp block);
AI-authored prose is labelled and cited.
**Limitations:** one template; no branding/theming.

## M11 — End-to-end testing and hardening
- Playwright E2E (register → discover → scan → validate → investigate → report), chaos cases
  (ZAP dies mid-scan, DB restart, worker restart mid-job, revoked grant mid-scan), load sanity,
  bandit + pip-audit + npm audit in CI, secret scanning, final isolation review, threat-model
  write-up, operator runbook.
**Acceptance:** E2E green against the mock adapter and against ZAP; every chaos case ends in a
defined state with correct audit trail; no high-severity SAST/dependency findings unexplained;
`docs/` matches the implementation.
**Limitations:** documented explicitly as the MVP boundary.

## Post-MVP (not in scope now)
M12 Nuclei adapter · M13 authenticated scanning · M14 scheduled/recurring assessments ·
M15 multi-tenant RBAC + SSO · M16 active scanning with a formal change-control workflow ·
M17 ticketing integrations.
