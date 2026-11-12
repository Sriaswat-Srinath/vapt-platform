# ADR-0002: Raw scanner observations are immutable and stored separately from findings

- Status: Accepted (2026-11-12)

## Context
`CLAUDE.md` rule 12 requires raw observations to be stored separately from normalised findings, with
provenance on every finding. Scanner mappings and validation rules will improve over time; past
conclusions must remain explainable and re-derivable.

## Decision
`raw_observations` rows are written verbatim from the adapter (payload + `payload_sha256`,
`request_sha256`, `response_sha256`; large bodies in the blob store) and are never updated or deleted
by normalisation, validation or risk scoring. `normalize()` is a pure function; findings link to
observations through `finding_observations`.

## Consequences
+ Any finding traces to the exact scanner record, adapter name and adapter version that produced it.
+ Historical scans can be re-normalised with an improved mapper and the delta is auditable.
+ Idempotency: re-running a phase over unchanged hashed inputs yields identical rows.
− Storage grows faster than a findings-only design; mitigated by blob storage and ADR-0011 retention.
− Two representations of "the same thing" must be kept consistent in the UI and the report.
