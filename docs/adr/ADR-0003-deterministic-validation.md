# ADR-0003: Validation is a deterministic rule engine; the LLM is advisory only

- Status: Accepted (2026-11-12)

## Context
A scanner alert is not a vulnerability. The platform must distinguish candidate / confirmed /
false positive / inconclusive / not applicable, and `CLAUDE.md` rules 4 and 13 forbid the LLM from
setting confirmed status.

## Decision
`validation/` holds versioned rule packs evaluating predicates over **stored evidence only**, driving
a state machine. Every transition writes a `validation_events` row with `rule_id`, `rule_version`,
`rule_inputs` and the `evidence_ids` relied on. `validation_events` carries a CHECK constraint
rejecting `actor_kind='agent'`. The agent's only output is an `agent_suggestions` row of kind
`triage_opinion`, which changes nothing until a human accepts it (see ADR-0007, ADR-0010).

## Consequences
+ Classification is reproducible and defensible in a report; no model version can alter history.
+ Rule packs are readable as data, which makes the safety test suite table-driven.
− Rule coverage is the limiting factor on confirmation rates; uncovered categories stay `candidate`
  with the evidence gap recorded, which is the honest outcome but looks like under-reporting.
− Rule versioning requires discipline: changing a rule's semantics demands a new version, not an edit.
