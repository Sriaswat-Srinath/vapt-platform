# ADR-0009: Dual control, and its limits in a single-operator environment

- Status: Accepted (2026-11-12)
- Relates to: D2, D7, confirmation 5

## Context
Intrusive and active scanning require two independent human approvals. In the local development
environment only one human may be available. Two accounts held by the same person are **not** dual
control, and the platform must not present them as such.

## Decision
1. **Roles and records.** `analyst`, `approver`, `admin` with Argon2-hashed API tokens. Every
   approval records both participants: `approvals.requested_by` and `approvals.decided_by`, each with
   timestamp, token id used, and trace id, in an immutable `audit_log` entry.
2. **Mechanical independence check.** A gate rejects `decided_by == requested_by`. This is necessary
   but **not sufficient** — it cannot prove two accounts are two people.
3. **Attested independence.** Independence is an explicit, recorded claim, not an inference. An admin
   registers each human identity in `operator_identities` with
   `independence_attested_by` + `attested_at` + `attestation_note`. The deployment-level flag
   `DUAL_CONTROL_AVAILABLE` (default `false`) may only be set true when ≥2 attested, distinct,
   active identities exist; a startup check verifies this and refuses to honour the flag otherwise.
4. **Gating.** Preflight gate 7 (`intrusive_approval`) denies when `DUAL_CONTROL_AVAILABLE` is false.
   Therefore **intrusive and active scan profiles remain disabled in a single-operator environment**,
   regardless of any grant or approval row that exists. `ACTIVE_SCAN_ENABLED=false` is an additional
   independent flag; both must be true plus an approved profile plus an explicit target scope.
5. **Honest labelling.** When `DUAL_CONTROL_AVAILABLE` is false, the UI shows "Dual control
   unavailable — single operator environment; intrusive profiles disabled", `GET /system/capabilities`
   reports it, and the generated report's **Limitations** section states it verbatim. Approvals
   recorded in such an environment are labelled `simulated_dual_control: true` in the API and the
   report, and are never described as independent human approval.
6. **No bypass.** There is no configuration that enables intrusive scanning while
   `DUAL_CONTROL_AVAILABLE` is false. Removing the gate requires a reviewed migration and an ADR
   supersession, not a config change.

## Consequences
+ The platform cannot overstate its assurance level; the weakened control is visible in the product
  and in every report produced under it.
+ The approval infrastructure is built and testable now, without pretending it is satisfied.
− Active scanning cannot be demonstrated end-to-end in a one-person lab. Accepted: M5/M7 acceptance
  uses passive profiles, and the active path is exercised through the mock adapter with two seeded
  **attested-as-test** identities, in tests only, clearly marked as not evidence of real dual control.
− An attestation is still a human claim; the platform records who made it and when, and nothing more
  is claimed for it.
