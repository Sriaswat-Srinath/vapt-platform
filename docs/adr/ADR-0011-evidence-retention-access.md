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
