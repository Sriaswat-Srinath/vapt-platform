# ADR-0005: Network-level egress denial is the primary scope control

- Status: Accepted (2026-11-12)

## Context
The brief requires network-level egress restrictions and explicitly forbids relying solely on
application-level validation. Application code has bugs; a routing topology that cannot reach the
internet has no bug to exploit.

## Decision
Four independent layers (see `SAFETY.md` §1). The primary control is topological: `core` and `lab`
are Docker networks with `internal: true`; ZAP and Juice Shop attach only to `lab`; the worker is
dual-homed `core`+`lab` and holds no LLM credentials; only `api`/`frontend` sit on `edge`, the sole
network with egress, and only to one configured LLM provider. Application-level scope validation is
the *secondary* control. An active egress probe records a `lab_isolation_checks` row; a failed or
stale check denies every scan at preflight gate 2.

## Consequences
+ A scope-validation bug cannot produce an external request: there is no route.
+ The isolation claim is tested, not asserted — and an induced misconfiguration must make the check
  fail (M1 acceptance criterion).
− The worker cannot reach EPSS/KEV feeds or a package index at runtime; threat intelligence is
  imported as dated offline snapshots (D8).
− Debugging inside `internal: true` networks is less convenient; accepted deliberately.
