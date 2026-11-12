# ADR-0004: CVSS is stored separately from the platform priority score

- Status: Accepted (2026-11-12)

## Context
CVSS describes a vulnerability class in the abstract. Analysts need prioritisation of *this* finding
on *this* asset, which depends on validation state, confidence, exposure, asset criticality and
threat intelligence. Conflating the two produces numbers that are neither.

## Decision
`risk_scores` stores `cvss_version / cvss_vector / cvss_base / cvss_source` and, in separate columns,
`priority_score` + `priority_band` from a versioned formula, with every input persisted in
`inputs jsonb` alongside `formula_version`. CVSS defaults come only from the curated `vuln_catalogue`
or an explicit scanner mapping; the LLM never produces a CVSS value or vector. Missing CVSS, EPSS or
KEV data yields NULL, never a fabricated or zero-filled value (see ADR-0008 of the decision log, D8).

## Consequences
+ Both numbers are explainable field-by-field in the UI and the report.
+ A `candidate` or `inconclusive` finding cannot outrank an equivalent `confirmed` one (formula
  invariant, property-tested).
− Two numbers invite "which is the real one?" confusion; the UI must always label them.
− The curated catalogue is manual work and will lag ZAP's rule set; unmapped detections are surfaced
  in their own report section rather than silently defaulted.
