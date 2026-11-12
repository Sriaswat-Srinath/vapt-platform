# Agentic Web VAPT Platform

AI-assisted web vulnerability assessment platform for **authorised, locally hosted mock targets
only**. Current state: **design phase (M0)** — no application code exists yet.

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
| [docs/adr/](docs/adr/README.md) | ADR-0001 … ADR-0011 |
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
- Evidence: synthetic only in the MVP, stored in a volume-backed blob store, unredacted content
  reachable only by `admin` with a justification and an audit entry (ADR-0011).
- No DoS, destructive tests, brute force, persistence, credential theft, exfiltration or
  exploitation beyond proof-of-presence. No Docker socket in scanner containers.
