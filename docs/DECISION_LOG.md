# Decision Log — approved 2026-11-12

Supersedes `OPEN_DECISIONS.md` (retained for history). These decisions are **binding**. Per
`CLAUDE.md` rule 16 and `SECURITY_ASSUMPTIONS.md` §E, if one becomes technically infeasible,
implementation stops and the trade-off is presented for approval before anything changes.

| # | Decision | Status | Modifications required by the owner |
|---|---|---|---|
| D1 | Celery + Redis for async jobs | **Approved** | — |
| D2 | `analyst` / `approver` / `admin` with hashed API tokens | **Approved** | Approval events record **both** participants' identities. Two accounts held by one person are **not** dual control; where only one human operates the environment this is documented explicitly and simulated approval is never represented as independent human approval → ADR-0009 |
| D3 | LLM egress from the api/agent component only | **Approved w/ modifications** | Exactly one explicitly configured provider; scanner workers airgapped; credentials from env vars, never committed; **credentials, tokens, personal data and sensitive raw evidence redacted before anything is sent to the LLM**; provider and model configurable → ADR-0010, `CONFIGURATION.md` |
| D4 | Long-lived ZAP daemon with per-job contexts | **Approved** | Explicit context cleanup, session isolation and job teardown; cross-job contamination prevented **and detected** → ADR-0008 |
| D5 | WeasyPrint for PDF | **Approved** | HTML and JSON reports remain available independently of PDF generation |
| D6 | Authenticated scanning | **Deferred** | Unauthenticated discovery and scanning initially; authentication entry points still recorded in the attack-surface inventory |
| D7 | Active scanning | **Approved w/ restrictions** | Separate, explicitly controlled capability; **disabled by default**; requires an approved profile + explicit target scope + **two independent human approvals**; if genuine dual control is unavailable, intrusive profiles stay disabled; local mock applications only → ADR-0009, gate 7 |
| D8 | EPSS/KEV as dated offline snapshots | **Approved** | Missing intelligence yields **NULL**, never a fabricated estimate |
| D9 | Fingerprint: parameter names in, values out | **Approved** | Per `SCANNER_INTEGRATION.md` §5 |
| D10 | Analyst override of validation state | **Approved** | Mandatory justification, timestamp, actor identity, immutable audit event; **the original automated validation result is preserved** (append-only `validation_events`, never overwritten) |
| D11 | Local volume-backed blob store, references in PostgreSQL | **Approved** | Access controls + configurable retention; **synthetic test evidence only in the MVP** → ADR-0011 |
| D12 | React Query + generated OpenAPI types | **Approved** | — |

## Confirmations

| # | Item | Resolution |
|---|---|---|
| 1 | Authorisation document | `lab/authorisation/MOCK-WEB-001.md` accepted. It authorises testing **only** against the locally hosted synthetic Juice Shop instance and explicitly grants **no** authorisation over any real Brakes India infrastructure. Drafted unsigned; an operator must complete and sign it, after which its SHA-256 is recorded in the scope grant |
| 2 | Mock asset | HTTP, container port `3000`, published host port `3000`, bound **exclusively to `127.0.0.1`** (startup validation refuses any non-loopback publish) |
| 3 | Network | `LAB_SUBNET=172.30.10.0/24`. Conflict check performed 2026-11-12: free (host Docker networks occupy `172.17.0.0/16`, `172.18.0.0/16`, `172.19.0.0/16`; host LAN `192.168.1.0/24`); re-verified by `make lab-check` before every `lab-up`. **Subnet membership is not authorisation** — the exact registered host and port allowlist is enforced in addition (gates 9–10) |
| 4 | Hostname | `shop.brakes-vapt.test` is a Docker network alias resolvable only inside `vapt_lab`. Workstation access is `http://127.0.0.1:3000`. **No hosts-file entry will be added** |
| 5 | Approver | Role and approval infrastructure built; `DUAL_CONTROL_AVAILABLE` defaults false and cannot be honoured without ≥2 attested, distinct, active identities. Intrusive scanning stays disabled until then, and the limitation appears in `/system/capabilities`, the UI and every report |
| 6 | LLM | Provider and model configurable; credentials read from env vars; provider/model/credential referenced in exactly one module (`agent/llm/provider.py`) and nowhere else |
| 7 | Git | Repository initialised; M0 architecture, plan and ADRs committed before M1. `.gitignore` excludes `.env*` (except `.env.example`), secrets, evidence, blob store, DB volumes, reports and scanner output |

## Architectural records

ADR-0001 modular monolith · ADR-0002 immutable raw observations · ADR-0003 deterministic validation ·
ADR-0004 CVSS separate from priority · ADR-0005 network egress denial primary · ADR-0006
resolve-once-and-pin · ADR-0007 agent proposes, humans decide · **ADR-0008 per-job scanner
isolation** · **ADR-0009 dual-control limits in a single-operator environment** · **ADR-0010 LLM
evidence redaction** · **ADR-0011 evidence retention and access controls**.
