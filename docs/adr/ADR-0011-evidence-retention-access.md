# ADR-0011: Evidence retention and access controls

- Status: Accepted (2026-11-12); **amended R2 (2026-11-12)**
- Relates to: D11, ADR-0002, ADR-0010

## Context
Evidence is both the product's core value and its largest liability: request/response bodies, headers
and snapshots containing secrets. It must be durable enough to defend a finding and bounded enough
not to become an indefinite secret store.

## Decision

**Storage.** Local volume-backed blob store at `EVIDENCE_BLOB_ROOT` (named Docker volume, not a bind
mount into the repo), content-addressed as `<sha256[0:2]>/<sha256>`; PostgreSQL holds only
`blob_path`, `content_sha256`, `media_type` and `bytes`. Writes are atomic (temp file + rename), files
are `0600`, owned by a dedicated non-root uid, and the volume is never mounted into a scanner
container. `content_addressed` storage deduplicates identical bodies across findings.

**Two tiers.**
- `evidence.content_redacted` — redacted text, readable by `analyst` and above; what the UI, the
  report and (after a second redaction pass, ADR-0010) the agent see.
- Blob store — the unredacted original, reachable **only** via
  `GET /evidence/{id}/content?raw=true`, which requires role `admin`, a justification string, and
  writes an `audit_log` entry recording actor, evidence id, justification and trace id. There is no
  bulk raw export endpoint. The agent has no code path to it at all.

**Retention.** Configurable per class, enforced by a scheduled worker task
(`tasks/retention.py`), all defaults stated in `CONFIGURATION.md`:
- `RETENTION_RAW_BLOB_DAYS` (default 90) — unredacted blobs deleted; the DB row persists with
  `blob_id` cleared (**R2 §7: `blob_path` is replaced by an `evidence_blobs` FK**) and
  `blob_purged_at` set, so provenance (hashes, adapter, rule id) survives the
  content.
- `RETENTION_REDACTED_EVIDENCE_DAYS` (default 365).
- `RETENTION_RAW_OBSERVATION_DAYS` (default 365) — payload JSONB purged to a hash-only stub.
- `RETENTION_AUDIT_DAYS` — **not configurable; audit is never pruned in the MVP.**
- Evidence referenced by a `report_artifacts` row that still exists is exempt from blob purge, so a
  delivered report never loses its supporting evidence silently.
- Purges are themselves audit-logged, with counts and the policy version applied.

**Deletion.** `DELETE /assets/{id}/evidence` (admin, justification required) performs a purge for one
asset. Deletion is always recorded; rows become hash-only stubs rather than vanishing, so a report's
provenance chain still resolves to "evidence existed, hash X, purged at T by actor Y".

**Backups.** The evidence volume is explicitly excluded from any convenience backup script in the
repo; backing up secret material is an operator decision, documented not automated.

**MVP posture.** Synthetic evidence only, from the local Juice Shop instance. No production or
customer data enters the system during MVP development. `.gitignore` excludes the evidence root,
blob store, database volumes and `.env*`; generated evidence is never committed.

## Consequences
+ Secrets live in exactly one place, behind one admin-only, justification-gated, audited endpoint.
+ Provenance outlives content: purging a body does not orphan or falsify a finding.
+ Retention is a deterministic scheduled job with recorded effects, not manual hygiene.
− Local volume storage is single-host: no replication, and a lost volume loses evidence while leaving
  findings intact (hash-only stubs). Acceptable for an MVP lab; an object-store backend is a later
  milestone.
− The report-artifact exemption means a long-lived report pins its evidence indefinitely; this is a
  deliberate correctness-over-minimisation trade, and the pinned set is reportable via
  `GET /system/retention/pinned`.

---

## Amendment R2 (2026-11-12) — the five mechanisms that must be defined before retention is built

Retention is not implemented until all five below are specified, schema-backed and tested. Full
procedures live in `EVIDENCE_LIFECYCLE.md`; this records the decisions.

### 7. Reference-aware blob deletion
Blobs become first-class rows rather than an implicit path string:

```
evidence_blobs(id, content_sha256 unique, byte_size, media_type,
               storage_path, state enum[present|pending_delete|purged|missing],
               created_at, last_verified_at, purged_at, purge_run_id FK NULL)
evidence(… , blob_id FK evidence_blobs NULL, blob_purged_at, …)   -- replaces blob_path
```

- Content addressing means **one blob, many evidence rows** (identical bodies deduplicate), so a path
  string could never have carried correct ownership. Reference counting is therefore mandatory.
- An **active reference** is an `evidence` row that is not itself purged **or** that is covered by an
  unreleased `evidence_pins` row (§9).
- **A blob is never unlinked while any active reference exists.** Enforced by three independent
  mechanisms: the FK from `evidence.blob_id`; a `SELECT … FOR UPDATE` on the `evidence_blobs` row
  with a **re-count inside the same transaction immediately before unlink**; and a post-unlink
  assertion. Counts are always computed, never trusted from a cached counter.
- Deletion is a staged state machine: `present → pending_delete` (committed) → unlink file →
  `purged` + `purged_at`. A row stuck in `pending_delete` is safe: readers treat it as unavailable,
  and the reconciler either completes or reverts it (§8).
- An **orphan sweeper** reports files on disk with no `evidence_blobs` row and rows whose file is
  missing (`state='missing'`), both audited. It reports; it does not delete on its own.

### 8. Recovery from interrupted purge operations
```
retention_runs(id, policy_version, state enum[planned|running|interrupted|completed|failed],
               started_at, finished_at, counts jsonb, actor_kind, error)
retention_run_items(id, run_id FK, target_kind enum[blob|evidence_row|raw_observation],
                    target_id, state enum[planned|unlinked|row_nulled|done|skipped_pinned|failed],
                    attempted_at, completed_at, error,
                    UNIQUE(run_id, target_kind, target_id))
```
- A run is **planned in full and committed before any destructive step**, so an interruption always
  leaves a complete, resumable plan — never an unknown partial.
- Every step is **idempotent** and keyed by item, so resumption re-executes safely: unlinking an
  already-absent file succeeds; nulling an already-null column succeeds.
- **Step ordering is chosen so the failure mode is safe:** unlink the file *first*, then null the DB
  reference. A crash between them leaves "row references a file that is gone" — detectable and
  repairable. The reverse order would leave "row says purged while the secret is still on disk", a
  silent retention failure. Safety beats tidiness.
- A worker-startup reconciler finds runs in `running` whose lease is stale, marks them `interrupted`,
  and resumes them item by item (audited). Auto-resume is deliberate: a half-finished purge is not a
  state to sit in. Items that fail twice are marked `failed` and reported; the run completes without
  them rather than blocking forever.
- `GET /system/retention/runs` exposes run and item state; every run and resumption is audit-logged.

### 9. Report evidence pinning semantics
```
evidence_pins(id, report_id FK, report_artifact_id FK, evidence_id FK,
              pins_blob bool, created_at, released_at NULL, release_reason)
```
- Pins are **explicit rows created at report generation time**, not an implicit join — so the pinned
  set is queryable, auditable and releasable, and retention logic never has to infer it.
- **A pin always covers the redacted evidence row. `pins_blob` defaults to `false`**, because reports
  embed redacted evidence only. The consequence is important and intended: generating a report does
  **not** extend the life of unredacted secret material. `pins_blob=true` only if an artifact ever
  embeds raw content, which no MVP template does.
- Pins are released when the artifact or report is deleted, or by an admin with a justification.
  Released pins stay as rows (`released_at` set) for audit. Once released, normal retention applies
  on the next run.
- Retention skips pinned targets with `state='skipped_pinned'` — visible, counted, never silent.
- `GET /system/retention/pinned` lists what is pinned, by which report, and since when.

### 10. Raw evidence restoration policy
**Purge is final. The MVP has no restoration capability.** Stated plainly rather than implied:

- There is no undelete, no trash, no soft-retained copy of an unlinked blob. Content-addressed
  storage means the bytes are gone.
- Restoration is possible **only** from an operator-managed backup, which this repository explicitly
  does not automate and whose existence the platform does not assume (ADR-0011 §Backups).
- A controlled request flow exists so restoration is never ad hoc:
  `raw_restoration_requests(id, evidence_id, requested_by, justification, state
  enum[requested|approved|rejected|restored|unavailable], decided_by, decided_at,
  restored_at, verified_sha256_match bool, note)`. Admin requests with justification; a second admin
  decides where dual control is available; the operator restores out-of-band; re-ingest **verifies
  `content_sha256` against the surviving DB record** and refuses on mismatch; every step is audited.
- Provenance survives purge regardless: hashes, adapter, rule id and timestamps remain, so a finding
  always resolves to "evidence existed, hash X, purged at T by actor Y" — a report never silently
  loses its chain.

### 11. Encryption-at-rest assumptions and limitations
**The MVP does not implement application-level encryption of evidence.** The honest statement of what
that means:

*Assumed:* the operator's host provides full-disk encryption (LUKS/FileVault/BitLocker) covering the
Docker volume root and the Postgres data directory. **The platform does not verify this and must not
claim it.** `/system/capabilities` reports `evidence_encryption: "none (host FDE assumed, unverified)"`
and the report's Limitations section says so.

*Therefore protected against:* offline theft of a powered-off disk or a decommissioned drive.

*Not protected against:* a root or container-escape attacker on the running host; any process that can
read the volume; copies made by backup tooling; file-level exposure through a misconfigured bind
mount; secrets in process memory; database dumps; and the host operator themselves. On a running
system, FDE provides no confidentiality for these blobs.

*Additional secrets at rest in the environment:* `SECRET_KEY`, `POSTGRES_PASSWORD`, `ZAP_API_KEY`,
`REDACTION_HMAC_KEY` and the LLM key live in the process environment / an operator-managed `.env`
that is git-ignored. They inherit exactly the same assumption and the same limitations.

*Why deferral is acceptable:* MVP evidence is **synthetic only** (D11) — deliberately vulnerable Juice
Shop data with no real credentials or personal data — so the realistic loss is low. Deferral is
acceptable *because of that constraint*, and the constraint is therefore part of the decision, not
incidental to it.

*Required before any non-synthetic data is ever stored:* application-level envelope encryption of
blobs (per-blob data key wrapped by a KMS/operator key), encrypted database columns for evidence
text, and a key-management and rotation design. Tracked as **open decision D13**; the platform must
not be pointed at non-synthetic targets until it is resolved. A startup warning fires whenever an
asset outside `environment='mock_lab'` exists — which the MVP's CHECK constraint already forbids.

---

## Amendment R3 (2026-11-12) — purge atomicity, and synthetic-only provenance

### 12. PostgreSQL transactions and filesystem operations are not, and cannot be, atomic together

There is no two-phase commit between Postgres and the filesystem. A transaction cannot be rolled back
once a file is unlinked, and an unlink cannot be undone when a transaction aborts. **We therefore do
not attempt atomicity.** Instead the crossing is made *recoverable*: intent is committed to the
database before any filesystem change, and the order is chosen so the only reachable inconsistency is
the safe, detectable one.

Each step boundary touches **exactly one** system — never both:

| Step | System | Operation | Committed outcome |
|---|---|---|---|
| **S0** | DB tx | plan the whole run: one `retention_run_items` row per candidate, `state='planned'` | a complete, resumable plan exists before anything is destroyed |
| **S1** | DB tx | `SELECT … FROM evidence_blobs WHERE id=:b FOR UPDATE`; **recount active references by query**; if > 0 ⇒ `skipped_referenced` / `skipped_pinned` and stop. Else `blob.state='pending_delete'`, `item.state='intent_committed'`, `attempts += 1` | **the crossing point.** After this commit, an absent file is *expected* |
| **S2** | filesystem | pre-unlink identity checks → `unlink(path)` → verify absence → `fsync` the containing directory | the bytes are gone **and durably gone** |
| **S3** | DB tx | re-assert recount == 0; `blob.state='purged'`, `purged_at`; `evidence.blob_purged_at` for referencing rows; `item.state='row_nulled'` → `'done'` | bookkeeping catches up to the filesystem |
| **S4** | DB tx | run counts; set `retention_state.halted` if any item is `failed` or any blob is unexpectedly `missing` | inconsistency stops further deletion |

### 12.1 Committed-intent state machine

```
planned ──S1──▶ intent_committed ──S2──▶ unlinked ──S3──▶ row_nulled ──▶ done
   │                   │                     │
   │                   │                     └─ file still present after unlink ⇒ failed + HALT
   │                   └─ pre-unlink identity check fails ⇒ failed + HALT (never unlink)
   └─ active reference found ⇒ skipped_referenced | skipped_pinned (terminal, not an error)
```

**Intent is the discriminator, never the filesystem.** A missing file is expected only when
`blob.state='pending_delete'` and an item for it exists; otherwise it is an unexpected loss recorded
as `blob.state='missing'`, raised as an integrity alert, audited, and **never** recorded as a purge.

### 12.2 Locking and the durability of the recount

- The recount is **computed by query** inside S1, under `FOR UPDATE` on the `evidence_blobs` row —
  never from a cached counter, and never only at planning time.
- A trigger rejects any new `evidence.blob_id` (or `report_artifacts.artifact_blob_id`) referencing a
  blob whose `state <> 'present'`. This is what makes S1's count durable across S2: a new reference
  cannot appear while deletion is in flight, so S3's re-assertion cannot fail spuriously.
- The recount re-runs on **every** attempt, so resumption is never a fast path that skips the check.
  A reference created between planning and S1 yields `skipped_referenced`.

### 12.3 Unlink verification (S2 in detail)

Before unlinking: `lstat` the path (must not be a symlink), assert the resolved real path is under
`EVIDENCE_BLOB_ROOT`, assert the path matches the content-addressed layout for
`content_sha256`, and assert `st_size == evidence_blobs.byte_size`. Any mismatch ⇒ `failed` + halt,
**without unlinking** — the platform refuses to delete a file it cannot positively identify as the
blob it intends to delete.

After unlinking: `stat` must raise `ENOENT` (a still-present file ⇒ `failed` + halt), and the
containing directory is `fsync`ed so the deletion survives power loss. Without that fsync a crash
could resurrect the file while the database claimed `purged` — the exact inconsistency this ordering
exists to prevent. `ENOENT` from the unlink itself is **success** (idempotent).

### 12.4 Crash recovery matrix

| Crash point | Observed state | Interpretation | Recovery |
|---|---|---|---|
| after S0 | items `planned`, nothing destroyed | plan intact | resume from S1; nothing lost |
| between S1 and S2 | blob `pending_delete`, file **present** | intent committed, unlink not done | re-run S2 (idempotent), then S3 |
| during S2 | blob `pending_delete`, file absent or partially handled | unlink done or indeterminate | re-run S2 (`ENOENT` ⇒ success), verify, then S3 |
| between S2 and S3 | blob `pending_delete`, file **absent** | **the expected inconsistency** — bytes gone, row stale | re-run S3; row ends `purged` |
| after S3 | blob `purged`, file absent | complete | mark item `done` if not already |
| any | blob `present`, file absent, **no intent** | unexpected loss | `state='missing'`, integrity alert, **halt**; never recorded as a purge |

The reverse inconsistency — *row says purged while the secret is still on disk* — is unreachable,
because S3 runs only after a verified, fsynced unlink. That asymmetry is the whole point of the
ordering.

### 12.5 Recovery is audited and halts on inconsistency

A worker-startup reconciler marks `running` runs with a stale lease as `interrupted` and resumes them
item by item. Every attempt writes an audit row (run, item, prior state, outcome, `actor_kind=system`,
trace id); resumption itself is audited as `retention_run_resumed`. An item exceeding
`RETENTION_ITEM_MAX_ATTEMPTS` is `failed`.

**Any `failed` item, or any unexpectedly `missing` blob, sets `retention_state.halted = true` with the
reason and offending ids. While halted, no new destructive run may start** (planning and dry-run still
work); the in-flight run finishes only items already proven safe. Clearing the halt requires an admin
acknowledgement with a justification, audited. This supersedes the R2 wording "the run completes
without it", which would have allowed deletions to continue past an unexplained inconsistency.

### 13. Synthetic-only enforcement rests on provenance, not on the `mock_lab` label

The `environment='mock_lab'` CHECK is metadata. The enforcement is:

1. **No evidence exists outside a job.** No API, import or admin-upload path writes
   `raw_observations` or `evidence`; both are worker-only writes, and `raw_observations.job_id` is
   `NOT NULL` with an FK. The mandatory chain is
   `evidence → raw_observation → scan_job → scope_decision(allow) → asset(mock_lab) →
   scope_grant(signed_verified)`.
2. **Ingestion re-validates provenance independently of request time.** Each observation carries its
   observed peer IP, host and port; ingestion rejects any whose peer IP ∉ `scan_jobs.pinned_ips` or
   whose host/port ≠ the registered asset — rejected and audited, never stored.
3. **Identity fields are immutable.** A BEFORE UPDATE trigger rejects changes to
   `assets.environment`, `hostname`, `protocol` and `port`; re-registration is required and audited.
   Relabelling gains nothing: gates 8–10 still require lab-resolver resolution into `allowed_cidrs`
   and the exact registered host and port, and ADR-0005's topology leaves the worker no other route.
   **Synthetic-only is enforced by the route; the label is metadata.**
4. **Chain integrity is checked, not assumed.** A scheduled job and
   `GET /system/provenance/verify` walk every evidence row against the chain, `asset_resolutions`
   history and the `lab_isolation_checks` record covering the job's window. Violations **quarantine**
   the finding: flagged, excluded from reports, audited.

Residual risk, stated rather than implied: direct database or Docker-daemon access can forge rows or
rewire networks. Forging consistently requires the job, scope decision, pinned IPs *and* isolation
record to agree, and the audit hash chain plus resolution history make disagreement visible —
containment, not elimination. Recorded as assumption **B8**.
