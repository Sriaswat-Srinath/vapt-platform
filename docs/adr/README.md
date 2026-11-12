# Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [0001](ADR-0001-modular-monolith.md) | Modular monolith over microservices | Accepted |
| [0002](ADR-0002-immutable-raw-observations.md) | Raw scanner observations immutable, separate from findings | Accepted |
| [0003](ADR-0003-deterministic-validation.md) | Deterministic validation engine; LLM advisory only | Accepted |
| [0004](ADR-0004-cvss-separate-from-priority.md) | CVSS stored separately from the platform priority score | Accepted |
| [0005](ADR-0005-network-egress-denial-primary.md) | Network-level egress denial is the primary scope control | Accepted |
| [0006](ADR-0006-resolve-once-pin-ip.md) | Resolve once, pin the IP, send an explicit Host header | Accepted |
| [0007](ADR-0007-agent-proposes-humans-decide.md) | The agent proposes; humans decide | Accepted |
| [0008](ADR-0008-per-job-scanner-isolation.md) | Per-job scanner isolation (ZAP daemon + per-job contexts) | Accepted; **amended R2, R3, R4** — revisit M11 |
| [0009](ADR-0009-dual-control-single-operator.md) | Dual control and its limits in a single-operator environment | Accepted; **amended R2** |
| [0010](ADR-0010-llm-evidence-redaction.md) | Redaction boundary for everything sent to the LLM | Accepted; **amended R2** |
| [0011](ADR-0011-evidence-retention-access.md) | Evidence retention and access controls | Accepted; **amended R2, R3** |
| [0012](ADR-0012-reachability-classes-and-egress-boundary.md) | Network reachability classes, host publishing, API egress boundary | Accepted (ratifies D19, D20) |

R2 amendments (2026-11-12) are appended to ADR-0008…0011 as `## Amendment R2` sections: global ZAP
daemon serialisation, approval invalidation and unbypassable dual-control verification, keyed HMAC
redaction identifiers with structural coverage, and the five retention mechanisms.

Format: Context / Decision / Consequences, with the trade-offs accepted stated explicitly. A decision
is changed by a new ADR that supersedes the old one — never by editing an accepted record.
