# MVP Security Invariants

Properties that must hold **regardless of future implementation changes**. These are automated tests
in `backend/tests/invariants/`, not documentation. The suite gates every merge.

An invariant is not a unit test of a function; it is an assertion about the system's externally
observable behaviour, written so that a refactor which breaks the property fails CI even if every
other test still passes.

## 1. The invariants

> Milestone column follows **ROADMAP v2** (re-sequenced 2026-11-12).

| # | Invariant | Asserted by | Milestone |
|---|---|---|---|
| **I1** | No unregistered asset can be scanned | unregistered, archived and non-`mock_lab` assets each denied at preflight; the persisted `ScopeDecision` and audit row are asserted, not just the HTTP status | M2 |
| **I2** | No scan starts without a valid ScopeDecision | job creation without a persisted `allow` decision raises; adapters independently re-check the decision and refuse; a forged job row still cannot start | M2 |
| **I3** | No active scan runs without genuine dual control | the five-case identity matrix (ADR-0009 R2 §9); only two distinct, active, attested identities satisfy the precondition, and every other gate still applies | M2 |
| **I4** | No scanner worker has internet access | TCP probes from the ZAP and Juice Shop containers to fixed public endpoints fail; public DNS does not resolve; `internal: true` and the absence of a gateway route asserted; **plus the induced-misconfiguration case proving the check can fail** | **M1** |
| **I5** | No LLM request contains unredacted evidence | canary secrets seeded in every fixture must not appear in any prompt, tool result, error, traceback or persisted agent row; the LLM client rejects a plain `str`; `RedactedText` cannot be constructed outside `agent/redaction.py` | M6 |
| **I6** | No finding becomes confirmed solely through LLM output | DB CHECK rejects `validation_events.actor_kind='agent'`; the output guard strips privileged fields; an accepted `agent_suggestions` row changes status only as a human-attributed event | M5 |
| **I7** | No referenced evidence blob is purged | shared-blob purge (two referencing rows ⇒ no unlink), pinned-blob skip, concurrent-reference race, and the pre-unlink identity checks; three independent guards exercised | M5 |
| **I8** | No new ZAP job starts while daemon state is dirty | dirty daemon ⇒ gate 13 denies on a **different** asset and a different profile too; dirty cannot be cleared except by a verification-gated reset | M3 |
| **I9** | No unsigned authorisation document activates a scope grant | grant activation refused while `document_state <> 'signed_verified'`; DB CHECK enforced; startup refuses to boot with a tampered active grant; document hash mismatch denies at gate 5 | M2 |
| **I10** | No report represents synthetic findings as actual Brakes India vulnerabilities | every artifact (HTML, PDF text, JSON, MD) must contain the synthetic-lab scope statement, the `mock_lab` environment label and `MOCK-WEB-001` named as a synthetic target; the Limitations section must be present and non-empty | M7 |
| **I11** | No plain hash of a secret value crosses the redaction boundary | no LLM-bound payload contains `content_sha256`, `redacted_sha256`, `payload_sha256`, `request_sha256` or `response_sha256`; refs are keyed HMAC only; `LLM_EXPOSE_CONTENT_HASHES=true` refuses startup; the HMAC key appears in no log, response, prompt or traceback | M6 |
| **I12** | Purge is idempotent and halts on inconsistency | the crash-recovery matrix (ADR-0011 R3 §12.4) replayed at each boundary; re-running any step is safe; an unexpectedly missing blob or a failed item sets `retention_state.halted` and **blocks new destructive runs** until an audited admin acknowledgement | M5 |
| **I13** | Cancellation completes within the SLA | revocation-to-terminal-state ≤ `CANCELLATION_SLA_SECONDS` (deterministic against the mock adapter, wall-clock against real ZAP); exceeding it yields `cancel_unconfirmed` + dirty daemon, never an indefinite wait | M3 |
| **I14** | Asset identity is immutable | `UPDATE` of `assets.environment`, `hostname`, `protocol` or `port` is rejected by trigger; the API PATCH whitelist excludes them; evidence ingestion rejects observations whose peer IP ∉ `pinned_ips` or whose host/port differ from the registered asset | M2 |

## 2. The manifest test

`tests/invariants/test_manifest.py` holds the invariant → milestone map above and asserts:

1. **Every invariant I1–I14 exists** as a collected test (or test module) — a deleted invariant fails
   CI rather than disappearing quietly.
2. **No invariant is skipped past its milestone.** A skip is permitted only while its milestone has
   not landed; the landed set is read from `docs/ROADMAP.md` status plus a committed
   `MILESTONE_STATE` marker. An invariant still skipped after its milestone is marked complete is a
   **failure**, not a skip.
3. **Skip reasons are explicit and machine-checked** — a bare `skip` with no milestone reference
   fails.
4. **The map is complete in both directions**: no invariant without a milestone, no orphan entry.

This exists because the realistic failure mode is not someone deleting a safety test; it is a safety
test quietly staying skipped while the milestone it guards ships green.

## 3. Rules

- Invariants assert **persisted state and audit rows**, not only HTTP status codes — a denial that
  does not record its `ScopeDecision` is a failed invariant.
- Invariants run against the **mock adapter** wherever possible so they execute in CI without ZAP or
  Juice Shop; I4 and the wall-clock half of I13 need the lab and run in the lab job.
- An invariant may not be weakened to accommodate an implementation. If an invariant and the
  implementation disagree, work stops and the conflict is raised (`CLAUDE.md` rule 16).
- Adding an invariant is cheap and encouraged; removing one requires an ADR.
