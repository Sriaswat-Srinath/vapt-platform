# ADR-0001: Modular monolith over microservices

- Status: Accepted (2026-11-12)
- Deciders: project owner, lead architect
- Supersedes: —

## Context
The safety-critical surface (scope policy, preflight gates, budgets, validation, risk) must be small,
auditable and synchronously testable. A distributed deployment would spread those controls across
network boundaries, where a failure mode is "request lost / service unreachable" rather than a
deterministic denial.

## Decision
One FastAPI application plus one Celery worker, organised as hard-bounded internal modules
(`api/ services/ safety/ discovery/ scanners/ normalization/ validation/ risk/ agent/ reporting/
domain/`). Boundaries are enforced mechanically by `import-linter` in CI, not by convention.

## Consequences
+ Scope decisions are in-process function calls — total, deterministic, table-testable.
+ One transaction boundary for state machines; no distributed-saga complexity.
+ Extraction stays cheap because imports are already constrained.
− Scaling is coarse-grained (whole app). Acceptable: the workload is a small number of long jobs.
− Module discipline depends on CI enforcement staying enabled; the import-linter contract is
  therefore treated as a safety test, not a lint nicety.
