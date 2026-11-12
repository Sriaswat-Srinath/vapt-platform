# Agentic Web VAPT Platform — Architecture (M0)

Status: **proposal, awaiting approval**. No application code exists yet.

## 1. Purpose and operating envelope

A platform for security analysts to assess **registered, locally hosted mock websites**: discover
attack surface, run OWASP ZAP, normalise findings, validate evidence deterministically, score risk,
investigate through a bounded LLM agent, and produce a report.

Non-negotiable envelope for the MVP:

- Only registered mock assets are scannable. Initial asset: `MOCK-WEB-001`, `shop.brakes-vapt.test`
  (OWASP Juice Shop), resolvable **only inside the isolated lab Docker network**.
- No production, staging, corporate, public or arbitrary-IP targets. No IoT/OT/firmware/infra testing.
- Scanner containers have **no route to the internet** (Docker `internal: true` networks), verified by
  a startup isolation probe. If the probe fails or is stale, scanner execution is **disabled** by a
  deterministic gate, not by convention.
- Excluded test classes: DoS, destructive writes, brute force, persistence, exfiltration, exploitation
  beyond proof-of-presence. Enforced by profile allowlists + path/method denylists in code.
- No Docker socket is ever mounted into a scanner container.

## 2. Component model

Modular monolith backend (one FastAPI app, hard module boundaries) + async worker + isolated lab.
Chosen over microservices because the safety-critical surface must be small, auditable and
synchronously testable. Boundaries are enforced by import rules (see §4) so extraction stays cheap.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ net: edge (has egress to LLM provider only)                               │
│   frontend (React/TS/Vite, nginx in prod)  ──▶  api (FastAPI)             │
└────────────────────────────────────────────────────────┬───────────────────┘
                                                         │
┌────────────────────────────────────────────────────────┴───────────────────┐
│ net: core (internal: true — no egress)                                     │
│   api ◀──▶ postgres        api ──▶ redis (queue) ◀── worker                │
│   worker ◀──▶ postgres                                                     │
└────────────────────────────────────────────────────────┬───────────────────┘
                                                         │ worker is dual-homed
┌────────────────────────────────────────────────────────┴───────────────────┐
│ net: lab (internal: true — no egress, no DNS leak)                         │
│   worker ──▶ zap (daemon, API key auth) ──▶ juiceshop                      │
│   worker ──▶ juiceshop (discovery crawler, direct)                         │
│   alias: shop.brakes-vapt.test → juiceshop container                       │
└────────────────────────────────────────────────────────────────────────────┘
```

Rationale for placement:

- The **worker holds no LLM credentials and has no egress**; the agent runs in the `api` process,
  which has no access to the `lab` network. Scanning and LLM inference are therefore physically
  separated — an injected instruction in scanner output cannot reach a target, and a compromised
  scan cannot reach the LLM provider.
- `shop.brakes-vapt.test` is a Docker **network alias**, not a public DNS name. Outside the `lab`
  network it does not resolve. Analysts browse the mock site via an explicit host port mapping.
- ZAP runs as a long-lived daemon with per-job isolated **contexts + sessions** (see
  `SCANNER_INTEGRATION.md` §6 for the per-job-container alternative, which is an open decision).

## 3. Layering

| Layer | Responsibility | May depend on |
|---|---|---|
| `api/` | HTTP, auth, serialisation, pagination. No business rules. | services, schemas |
| `services/` | Use-case orchestration, transactions, state machines. | domain, safety, adapters, repos |
| `safety/` | Scope policy, preflight gates, rate/concurrency/timeout budgets, isolation checks. | domain only |
| `discovery/` | Crawl, endpoint/param/form/header extraction, inventory build. | safety, domain |
| `scanners/` | Adapter protocol + ZAP/mock/Nuclei adapters, raw capture. | safety, domain |
| `normalization/` | Raw observation → `NormalizedFinding`, fingerprinting, dedup. | domain |
| `validation/` | Deterministic rule packs, validation state machine. | domain |
| `risk/` | CVSS storage, priority score formula, versioned. | domain |
| `agent/` | LangGraph graph, tool catalogue, output guard. | services (read-only facades) |
| `reporting/` | Report assembly, renderers (HTML/PDF/JSON). | services (read facades) |
| `domain/` | Entities, enums, value objects, pure functions. Zero I/O. | — |

Hard rules, enforced by `import-linter` in CI:

- `agent/` must not import `safety/`, `scanners/`, `subprocess`, `httpx`, or any write repository.
  It reaches data only through `agent/tools/` which wrap read-only service facades.
- `safety/`, `validation/`, `risk/` must not import `agent/` or any LLM library.
- `api/` must not import `scanners/` or `validation/` directly.

## 4. Directory structure

```
VAPT/
├── CLAUDE.md
├── README.md
├── Makefile                          # dev entrypoints: up, down, test, lint, lab-check
├── docker-compose.yml                # api, worker, db, redis, frontend
├── docker-compose.lab.yml            # zap, juiceshop, lab network (internal)
├── docker-compose.override.yml       # dev-only conveniences
├── .env.example
├── docs/
│   ├── ARCHITECTURE.md  DATA_MODEL.md  API.md  AGENT.md
│   ├── SCANNER_INTEGRATION.md  SAFETY.md  DEPENDENCIES.md
│   ├── RISKS.md  ROADMAP.md  OPEN_DECISIONS.md  DATA_FLOW.md
│   └── adr/ADR-0001-....md
├── backend/
│   ├── pyproject.toml                # ruff, mypy --strict, pytest, import-linter config
│   ├── alembic.ini
│   ├── migrations/versions/
│   ├── app/
│   │   ├── main.py  config.py  deps.py  logging.py
│   │   ├── api/v1/{assets,scope,discovery,scans,findings,evidence,risk,
│   │   │            agent,reports,audit,system}.py
│   │   ├── schemas/                  # pydantic request/response DTOs
│   │   ├── domain/
│   │   │   ├── enums.py  entities.py  errors.py
│   │   │   └── fingerprint.py
│   │   ├── db/{base.py,session.py,models/,repositories/}
│   │   ├── safety/
│   │   │   ├── scope_policy.py       # pure: ScopeRequest -> ScopeDecision
│   │   │   ├── target_resolver.py    # DNS + CIDR + port validation
│   │   │   ├── redirect_guard.py
│   │   │   ├── budgets.py            # rate, concurrency, timeout, request cap
│   │   │   ├── preflight.py          # ordered gate chain
│   │   │   ├── isolation.py          # egress probe + LabIsolationCheck
│   │   │   └── audit.py
│   │   ├── discovery/{crawler.py,extractors/,inventory.py,classify.py}
│   │   ├── scanners/
│   │   │   ├── base.py               # ScannerAdapter protocol
│   │   │   ├── registry.py  profiles.py
│   │   │   ├── zap/{adapter.py,client.py,mapping.py}
│   │   │   ├── mock/adapter.py       # default adapter
│   │   │   └── nuclei/               # M12+
│   │   ├── normalization/{mapper.py,dedup.py,severity.py}
│   │   ├── validation/{engine.py,state_machine.py,rules/}
│   │   ├── risk/{cvss.py,priority.py,catalogue.py}
│   │   ├── agent/
│   │   │   ├── graph.py  state.py  prompts/
│   │   │   ├── tools/{catalogue.py,read_findings.py,read_evidence.py,...}
│   │   │   ├── guard.py              # strips privileged fields, enforces citations
│   │   │   └── llm/{provider.py,anthropic.py,fake.py}
│   │   ├── reporting/{assembler.py,renderers/,templates/}
│   │   └── worker/{celery_app.py,tasks/,cancellation.py}
│   └── tests/
│       ├── unit/        # domain, safety, validation, risk, normalization (no I/O)
│       ├── integration/ # api + db (testcontainers/pg)
│       ├── safety/      # scope-enforcement suite, must stay green to ship anything
│       ├── scanners/    # mock adapter + recorded ZAP fixtures (vcr-style)
│       ├── agent/       # fake LLM, tool-boundary and guard tests
│       └── fixtures/
├── frontend/
│   ├── package.json  vite.config.ts  tsconfig.json
│   └── src/
│       ├── main.tsx  App.tsx  router.tsx
│       ├── api/{client.ts,generated/}   # types generated from OpenAPI
│       ├── pages/{Overview,Assets,AttackSurface,Scans,Findings,
│       │          FindingDetail,Assistant,Reports}/
│       ├── components/  hooks/  lib/
│       └── __tests__/                   # vitest + RTL
├── lab/
│   ├── README.md
│   ├── juiceshop/{Dockerfile,config.yaml}
│   ├── zap/{Dockerfile,zap-baseline-policy.xml,excludes.txt}
│   └── seed/MOCK-WEB-001.json           # registered asset + scope grant fixture
└── scripts/{lab_isolation_check.sh,seed_dev.py,gen_openapi_types.sh}
```

## 5. Cross-cutting concerns

- **Audit log**: append-only `audit_log` table. Every scope decision, approval, job transition,
  adapter invocation, validation transition, agent tool call and report export writes one row with
  actor (human or `agent:<session>`), action, subject, before/after hash, correlation id.
- **Correlation**: one `trace_id` per request / per job, propagated into worker tasks, agent runs and
  audit rows. Structured JSON logs.
- **Idempotency**: `scan_jobs.idempotency_key`, `findings.fingerprint`, `endpoints` natural key.
  Re-running normalisation or validation for a job is a no-op if inputs are unchanged (inputs hashed).
- **Determinism**: scope, validation, risk, budgets are pure Python with versioned rule/formula ids
  recorded on every output row, so any historical decision is reproducible.
- **Config**: pydantic-settings, fail-fast on missing secrets. `SCANNER_EXECUTION_ENABLED` defaults
  to `false`; `ACTIVE_SCAN_ENABLED` defaults to `false`; adapter default is `mock`.

See `DATA_FLOW.md` for the asset→report walkthrough, and `OPEN_DECISIONS.md` for what I need from you
before M1.

---

## 6. Amendments from the approved decision log (2026-11-12)

- Networks are named `vapt_edge` / `vapt_core` / `vapt_lab`; `vapt_lab` uses **`172.30.10.0/24`**
  (verified free on this host, re-checked by `make lab-check`). Subnet membership is **not**
  authorisation — the exact registered host and port allowlist still applies.
- The mock target publishes container port 3000 on **`127.0.0.1:3000` only**; a non-loopback publish
  is refused at startup. `shop.brakes-vapt.test` stays a `vapt_lab` network alias with **no**
  workstation hosts-file entry; the workstation uses `http://127.0.0.1:3000`.
- A new module `agent/redaction.py` sits on the only egress path to the LLM; agent tools return
  `RedactedText`, which only the redactor can construct (ADR-0010). Import-linter gains a contract
  forbidding `agent/` from importing blob or raw-evidence readers.
- `safety/dual_control.py` owns identity attestation and the `DUAL_CONTROL_AVAILABLE` startup check;
  intrusive and active profiles are disabled whenever genuine dual control is unavailable (ADR-0009).
- `scanners/zap/isolation.py` owns the per-job session/context lifecycle, the empty-store assertions
  and the daemon-dirty flag (ADR-0008).
- `worker/tasks/retention.py` owns the scheduled, audited evidence purge (ADR-0011).
- Directory additions: `lab/authorisation/MOCK-WEB-001.md`, `docs/CONFIGURATION.md`,
  `docs/SECURITY_ASSUMPTIONS.md`, `docs/DECISION_LOG.md`, `docs/adr/ADR-0001…0011`.
