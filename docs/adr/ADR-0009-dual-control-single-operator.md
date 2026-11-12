# ADR-0009: Dual control, and its limits in a single-operator environment

- Status: Accepted (2026-11-12); **amended R2 (2026-11-12)**
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

---

## Amendment R2 (2026-11-12) — approval invalidation and unbypassable verification

### 7. Approvals are invalidated when an identity stops qualifying
An approval is **not** a permanent artefact. `approvals.independence_verified` records what was true
at decision time (evidence), but authority is re-derived live.

**Live re-evaluation.** Gate 7 re-checks, at every evaluation, that `requested_by` and `decided_by`
both still resolve to `operator_identities` rows that are **attested, distinct and active**. A stored
`approved` state is never sufficient on its own.

**Eager invalidation.** Revoking an identity, deactivating it, or withdrawing its attestation
triggers `services/dual_control.invalidate_dependents()` in the same transaction:
- every dependent `approvals` row moves to the new state **`invalidated`** with
  `invalidated_at`, `invalidated_reason` and `invalidating_identity_id`;
- in-flight jobs whose authority derived from such an approval are marked `cancelling` and stop at
  the next **cancellation checkpoint** with `stop_reason='approval_invalidated'` — bounded by
  `CANCELLATION_SLA_SECONDS` (120 s ceiling; see ADR-0008 R3 §14, which corrects the looser
  "next phase boundary" wording), consistent with grant revocation;
- every invalidation is audit-logged, and the UI surfaces it on the job and the approval.

Invalidation is **not reversible by re-activating the identity**: a fresh approval must be requested
and decided. Re-attesting cannot resurrect authority that was already withdrawn.

### 8. Configuration cannot bypass startup verification
`DUAL_CONTROL_AVAILABLE` is an **input, never a trusted value**. The effective value is computed, not
read:

```
effective_dual_control = DUAL_CONTROL_AVAILABLE_flag
                         AND count(operator_identities
                                   WHERE attested AND active AND distinct_analyst) >= 2
```

- Computed at startup (a `true` flag with an unmet precondition is forced false, logged, audited, and
  reported through `/system/capabilities`), **and recomputed at every gate 7 evaluation**, so a
  revocation takes effect without a restart and a restart cannot be used to re-enable anything.
- There is **no** environment variable, database column, API field, feature flag or profile setting
  that can set the effective value directly, and none that can skip the recomputation. Intrusive
  authority therefore cannot be granted by configuration alone.
- `ACTIVE_SCAN_ENABLED` is an independent **additional** requirement (AND, never OR).
- Removing or weakening this computation requires a superseding ADR and a reviewed migration.

### 9. Required test matrix (M3; all five cases, all must assert the persisted ScopeDecision)

| Case | Identity precondition | Expected |
|---|---|---|
| 1. One human identity | not met | intrusive **denied** at gate 7 |
| 2. Two accounts belonging to one identity | not met (same `operator_identities` row / same attested human) | **denied** |
| 3. Two identities, no attestation | not met | **denied** |
| 4. Two attested but **inactive** identities | not met | **denied** |
| 5. Two distinct, active, attested identities | **met** | gate 7's identity precondition satisfied — **and every other gate still applies** |

Case 5 satisfies *only* the identity precondition. The job still requires
`SCANNER_EXECUTION_ENABLED`, a fresh isolation check, an active grant whose authorisation document is
**signed and verified**, `profile ∈ grant.allowed_profiles`, `ACTIVE_SCAN_ENABLED`,
`grant.intrusive_allowed`, an unexpired approval with `decided_by != requested_by`, in-scope
resolution, port and host allowlists, and daemon availability. Passing case 5 must not be mistaken
for, or tested as, "intrusive scanning enabled".

Additional cases: identity revoked **after** approval ⇒ approval `invalidated` and in-flight job
cancelled within the cancellation SLA (ADR-0008 R3 §14); attestation withdrawn after approval ⇒ same; attempt to set
`DUAL_CONTROL_AVAILABLE=true` with one identity ⇒ forced false and audited; attempt to grant
intrusive authority by editing a profile, grant or approval row directly ⇒ still denied by live
re-evaluation.
