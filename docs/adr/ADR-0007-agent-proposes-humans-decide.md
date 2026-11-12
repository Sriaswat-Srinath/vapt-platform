# ADR-0007: The agent proposes; humans decide

- Status: Accepted (2026-11-12)

## Context
`CLAUDE.md` rules 5 and 13 restrict the LLM to an allowlisted tool catalogue and forbid it from
setting status, scores, scope or rate limits. Convenience pressure to let the agent "just mark this a
false positive" is the predictable failure mode.

## Decision
The agent has no network client, no shell, no filesystem and no write repository (enforced by
import-linter and by the absence of such tools in `agent/tools/catalogue.py`). Its 11 read tools are
asset-scoped and argument-validated; no tool accepts a URL, hostname, shell string, SQL or file path.
Its only write path is an `agent_suggestions` row in state `proposed`. `propose_rescan` never starts
a scan. An output guard enforces the response schema, requires a citation to a retrieved
`finding_id`/`evidence_id` for every factual claim, strips privileged fields, and halts the run
(`halted_by_guard`) on violation.

## Consequences
+ Agent compromise or prompt injection yields, at worst, a bad suggestion a human must accept.
+ Every tool call is persisted with `allowed` / `denial_reason`, making agent behaviour auditable.
− Analysts cannot delegate triage to the agent; throughput gains come from explanation, not action.
− Citation enforcement will sometimes halt otherwise-useful answers; default is to halt rather than
  emit uncited claims.
