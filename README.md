# Agentic Web VAPT Platform

AI-assisted web vulnerability assessment for **authorised, locally hosted synthetic targets
only**. The product is a scanner pipeline, but most of the engineering is in the machinery that
**refuses** to scan, and in making every refusal legible.

> **No live scan has ever run.** Every finding, figure and report in this repository derives from
> hand-authored, scanner-shaped fixtures. The authorisation document for the lab target is an
> unsigned draft, scanner execution is disabled, and the preflight chain denies accordingly. That
> is the system working as designed, and the reports say so in their own words.
>
> `brakes-vapt.test` is a **local fiction** using the reserved `.test` TLD (RFC 6761). It resolves
> only inside a Docker network on one laptop. Nothing here describes, touches or is authorised to
> touch any real production, staging or corporate system.

## What is built

| Area | State |
|---|---|
| Asset, scope and authorisation management | 13-gate deterministic preflight chain, evaluated twice (API and worker) |
| Containment | 5 Docker networks, 118 network probes, 46 lab probes, plus scripts that deliberately break each control to prove the checks can fail |
| Discovery | endpoints, parameters, forms, headers, cookies → deterministic candidate tests |
| Scanner integration | adapter contract, ZAP + mock adapters, exclusive daemon lease, measured cancellation |
| Findings | fingerprint dedup, redaction on write, content-addressed evidence, five validation states from deterministic rule packs, CVSS from a curated catalogue |
| Taxonomy and coverage | 20 categories as first-class data; coverage reports **the zeroes**, including what this build cannot detect |
| Reporting | nine sections in HTML / JSON / PDF, with limitations derived from what actually happened |
| AI analyst | advisory only — a fixed tool catalogue, a refusing outbound boundary, and a conversational mode whose every tool is a **read** |
| Operations | retention with a halting purge, rate limiting, hash-chained audit, CI, lint and types |

14 security invariants, each with an implemented test and a manifest test that fails if one is
ever quietly skipped.

## Start here

* [docs/PROJECT_EXPLAINED.txt](docs/PROJECT_EXPLAINED.txt) — the system at a high level, then in detail
* [docs/GAPS.txt](docs/GAPS.txt) — what is **not** done, grouped by what would close it
* [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) — one rehearsed end-to-end journey

```bash
make lab-up net-up        # lab and application plane
make db-migrate db-seed   # schema and seed data
make lab-check            # containment, measured rather than assumed
make m9-readiness         # what remains before a first genuine assessment
```

Read `CLAUDE.md` for the engineering rules, then the design set in `docs/`:

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | component model, network topology, layering, directory structure |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | PostgreSQL schema, enums, constraints, retention |
| [docs/API.md](docs/API.md) | REST surface, conventions, error and denial shapes |
| [docs/SAFETY.md](docs/SAFETY.md) | scope policy, preflight gates, runtime budgets, isolation, LLM prohibitions |
| [docs/SCANNER_INTEGRATION.md](docs/SCANNER_INTEGRATION.md) | adapter protocol, ZAP/mock/Nuclei adapters, normalisation and dedup |
| [docs/AGENT.md](docs/AGENT.md) | LangGraph graph, tool catalogue, output guard, budgets |
| [docs/DATA_FLOW.md](docs/DATA_FLOW.md) | asset selection → report, end to end |
| [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) | pinned dependencies and images |
| [docs/RISKS.md](docs/RISKS.md) | implementation risks and mitigations |
| [docs/ROADMAP.md](docs/ROADMAP.md) | M0–M11 with acceptance criteria |
| [docs/DECISION_LOG.md](docs/DECISION_LOG.md) | **binding** decisions D1–D12 as approved, with modifications |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | every setting, its default and its startup validation |
| [docs/SECURITY_ASSUMPTIONS.md](docs/SECURITY_ASSUMPTIONS.md) | what the safety claims depend on, residual risk, accepted limitations |
| [docs/SCANNER_LIFECYCLE.md](docs/SCANNER_LIFECYCLE.md) | ZAP locks, job states, teardown, dirty-daemon recovery |
| [docs/REDACTION_DATAFLOW.md](docs/REDACTION_DATAFLOW.md) | what reaches the LLM, and how it is redacted |
| [docs/EVIDENCE_LIFECYCLE.md](docs/EVIDENCE_LIFECYCLE.md) | capture → storage → access → pin → purge |
| [docs/INVARIANTS.md](docs/INVARIANTS.md) | I1–I14 security invariants and the manifest test |
| [docs/M1_ACCEPTANCE.md](docs/M1_ACCEPTANCE.md) | M1 scope and acceptance criteria |
| [docs/M1_REPORT.md](docs/M1_REPORT.md) | M1 results, evidence, deviations D19–D23 and their ratification |
| [docs/NETWORK_ARCHITECTURE.md](docs/NETWORK_ARCHITECTURE.md) | M1→M2 per-component network access, reachability classes, API egress boundary |
| [docs/MVP_PLAN.md](docs/MVP_PLAN.md) | **phased MVP plan**: reuse inventory, dependencies, acceptance, carried conditions |
| [docs/MVP_PHASE1_REPORT.md](docs/MVP_PHASE1_REPORT.md) | phase 1: real datastores + proxy security review |
| [docs/MVP_PHASE2_REPORT.md](docs/MVP_PHASE2_REPORT.md) | phase 2: backend core — API, schema, auth, gate chain, audit |
| [docs/MVP_PHASE3_REPORT.md](docs/MVP_PHASE3_REPORT.md) | phase 3: worker, discovery, attack-surface inventory, candidate tests |
| [docs/MVP_PHASE4_REPORT.md](docs/MVP_PHASE4_REPORT.md) | phase 4: scanner adapters, raw observations, daemon lease, cancellation |
| [docs/MVP_PHASE5_REPORT.md](docs/MVP_PHASE5_REPORT.md) | phase 5: findings, evidence, deterministic validation, CVSS |
| [docs/MVP_SCOPE.md](docs/MVP_SCOPE.md) | **adopted MVP scope**, build/defer, reconciliation with binding decisions, the open ruling on active tests |
| [docs/M1_5_PLAN.md](docs/M1_5_PLAN.md) | M1.5 scope and the five owner corrections |
| [docs/M1_5_REPORT.md](docs/M1_5_REPORT.md) | M1.5 results: 91 probes, induced-failure evidence, limitations |
| [docs/M2_PLAN.md](docs/M2_PLAN.md) | M2 scope, deliverables, acceptance (v2; pending approval) |
| [lab/README.md](lab/README.md) | lab runbook: bring-up, checks, recovery, forwarder |
| [docs/adr/](docs/adr/README.md) | ADR-0001 … ADR-0011 (0008–0011 amended R2) |
| [docs/OPEN_DECISIONS.md](docs/OPEN_DECISIONS.md) | superseded; retained for history |

## Hard boundaries

- Only registered mock assets with an active `ScopeGrant` are scannable. Initial asset
  `MOCK-WEB-001` = `shop.brakes-vapt.test` (OWASP Juice Shop), resolvable only inside the isolated
  lab network.
- Scanner containers have no internet route; scanning is gated on a passing egress-isolation probe.
- Scanner execution and active scanning are **disabled by default**; the mock adapter is the default.
- Intrusive and active scanning additionally require two **independent** human approvals. In a
  single-operator environment genuine dual control does not exist, so intrusive profiles stay
  disabled and no simulated approval is ever presented as independent human approval (ADR-0009).
- Everything sent to the LLM passes a mandatory redaction boundary; the scanner worker is airgapped
  and holds no LLM credentials (ADR-0010).
- The LLM may only call allowlisted read tools and may propose, never decide. It cannot set validation
  status, CVSS, risk scores, scope or rate limits, and cannot run commands.
- One ZAP job runs at a time platform-wide, under a global daemon lease; unproven teardown marks the
  daemon dirty and blocks all scanner jobs until an audited admin reset (ADR-0008 R2).
- Scanner execution is **currently denied**: `lab/authorisation/MOCK-WEB-001.md` is an unsigned draft,
  and no ScopeGrant can be activated from it.
- Evidence: synthetic only in the MVP, stored in a volume-backed blob store, unredacted content
  reachable only by `admin` with a justification and an audit entry (ADR-0011).
- No DoS, destructive tests, brute force, persistence, credential theft, exfiltration or
  exploitation beyond proof-of-presence. No Docker socket in scanner containers.
