# Evidence Lifecycle: capture → storage → access → pin → purge

Normative for M6/M10/M11. Implements ADR-0011 + R2. Retention is **not implemented** until every
section here is schema-backed and tested.

## 1. Capture and storage

```
scanner / crawler response
  └─ STAGE 1 redaction (structure-aware)
     ├─ evidence.content_redacted      ← redacted text, analyst-readable
     ├─ evidence.redacted_sha256
     └─ evidence_blobs                 ← the unredacted original
        • content-addressed: <sha256[0:2]>/<sha256>
        • atomic write: temp file in the same dir + fsync + rename
        • mode 0600, dedicated non-root uid, named volume
        • NEVER mounted into a scanner container
        • one blob ↔ many evidence rows (identical bodies deduplicate)
```

`evidence.blob_id` is a foreign key to `evidence_blobs` — the R2 change from a bare `blob_path`
string, which could not express shared ownership and so could not be deleted safely.

## 2. Access tiers

| Tier | Who | How | Controls |
|---|---|---|---|
| Redacted | `analyst`+ | `GET /evidence/{id}/content` | role check, audit |
| Redacted (re-redacted) | the agent | tool results only | ADR-0010 boundary |
| **Unredacted** | **`admin` only** | `GET /evidence/{id}/content?raw=true` | justification **required**, audit row with actor + evidence id + justification + trace id, rate-limited, **no bulk export endpoint**, role not lowerable by configuration |
| None | the agent | — | no direct or indirect path (ADR-0010 §10) |

## 3. Pinning (report generation)

At artifact creation, explicit `evidence_pins` rows are written for every evidence row the artifact
cites. `pins_blob` defaults to **false**: reports embed redacted evidence, so **generating a report
does not extend the life of unredacted secret material**. Pins are released when the artifact or
report is deleted, or by an admin with justification; released rows are retained (`released_at`) for
audit. Retention skips pinned targets as `skipped_pinned` — counted and visible, never silent.
`GET /system/retention/pinned` answers "what is pinned, by which report, since when".

## 4. Purge

### 4.1 Plan-then-act
A retention run is **planned in full and committed before any destructive step**: every candidate
becomes a `retention_run_items` row in state `planned`. An interruption therefore always leaves a
complete, resumable plan rather than an unknown partial state.

Candidates by policy (defaults in `CONFIGURATION.md`): raw blobs > `RETENTION_RAW_BLOB_DAYS` (90) ·
redacted evidence > `RETENTION_REDACTED_EVIDENCE_DAYS` (365) · raw observation payloads >
`RETENTION_RAW_OBSERVATION_DAYS` (365). Audit is **never** purged.

### 4.2 Two systems that cannot be atomic together

**PostgreSQL transactions and filesystem operations cannot be made atomic.** There is no two-phase
commit between them: a transaction cannot roll back an unlink, and an unlink cannot be undone when a
transaction aborts. Atomicity is therefore **not attempted**. Instead intent is committed to the
database before any filesystem change, and the ordering guarantees that the only reachable
inconsistency is the safe, detectable one. Each step touches exactly one system:

| Step | System | Operation |
|---|---|---|
| **S0** | DB tx | plan the run: one `retention_run_items` row per candidate, `state='planned'` |
| **S1** | DB tx | `FOR UPDATE` on the blob row → **recount active references by query** → if > 0 stop (`skipped_referenced`/`skipped_pinned`); else `blob.state='pending_delete'`, `item.state='intent_committed'`, `attempts += 1` |
| **S2** | filesystem | pre-unlink identity checks → `unlink` → verify absence → `fsync` the directory |
| **S3** | DB tx | re-assert recount == 0 → `blob.state='purged'`, `purged_at`; `evidence.blob_purged_at`; `item` → `row_nulled` → `done` |
| **S4** | DB tx | run counts; set `retention_state.halted` on any `failed` item or unexpectedly `missing` blob |

S1 is the crossing point: **after it commits, an absent file is expected.** Before it, an absent file
is an unexplained loss.

```
planned ──S1──▶ intent_committed ──S2──▶ unlinked ──S3──▶ row_nulled ──▶ done
   │                   │                     │
   │                   │                     └─ file still present ⇒ failed + HALT
   │                   └─ identity check fails ⇒ failed + HALT (never unlink)
   └─ active reference ⇒ skipped_referenced | skipped_pinned (terminal, not an error)
```

**Locking and recount durability.** The recount is computed by query inside S1 under `FOR UPDATE` —
never cached, never only at planning time, and re-run on **every** attempt. A trigger rejects any new
`evidence.blob_id` or `report_artifacts.artifact_blob_id` referencing a blob whose `state <> 'present'`,
which is what makes S1's count durable across S2 so S3's re-assertion cannot fail spuriously.

**Unlink verification (S2).** Before: `lstat` (must not be a symlink), resolved real path under
`EVIDENCE_BLOB_ROOT`, path matches the content-addressed layout for `content_sha256`, and
`st_size == byte_size`. Any mismatch ⇒ `failed` + halt **without unlinking** — the platform refuses to
delete a file it cannot positively identify. After: `stat` must raise `ENOENT` (a still-present file ⇒
`failed` + halt), and the containing directory is `fsync`ed so the deletion survives power loss —
without that fsync a crash could resurrect a file the database calls `purged`. `ENOENT` from the
unlink itself is success (idempotent).

**A blob is never unlinked while an active reference exists** — the FK, the `FOR UPDATE` recount, the
reference-guard trigger and the post-unlink assertion are four independent guards.

### 4.3 Ordering is chosen for a safe failure mode
Unlink **before** nulling the DB reference. A crash between them leaves *"the row references a file
that is gone"* — detectable and repairable. The reverse order would leave *"the row says purged while
the secret is still on disk"*, a silent retention failure, and S3-after-verified-unlink makes it
unreachable. Correctness of the secret-removal guarantee beats bookkeeping tidiness.

### 4.4 Interrupted-purge recovery

| Crash point | Observed | Interpretation | Recovery |
|---|---|---|---|
| after S0 | items `planned` | plan intact | resume from S1 |
| between S1 and S2 | `pending_delete`, file present | intent committed, unlink not done | re-run S2, then S3 |
| during S2 | `pending_delete`, indeterminate | unlink done or not | re-run S2 (`ENOENT` ⇒ success), verify, then S3 |
| between S2 and S3 | `pending_delete`, file absent | **the expected inconsistency** | re-run S3; row ends `purged` |
| after S3 | `purged`, file absent | complete | mark `done` if not already |
| any | `present`, file absent, **no intent** | unexpected loss | `state='missing'`, integrity alert, **halt**; never recorded as a purge |

Every step is idempotent and keyed by `(run_id, target_kind, target_id)`. A worker-startup reconciler
marks `running` runs with a stale lease as `interrupted` and resumes them item by item. Every attempt
is audited (run, item, prior state, outcome, `actor_kind=system`, trace id); resumption is audited as
`retention_run_resumed`. Auto-resume is deliberate — a half-finished purge is not a state to sit in.

**Halt on inconsistency.** An item exceeding `RETENTION_ITEM_MAX_ATTEMPTS` is `failed`; any `failed`
item or unexpectedly `missing` blob sets `retention_state.halted` with the reason and offending ids.
**While halted, no new destructive run may start** (planning and dry-run still work); the in-flight run
finishes only items already proven safe. Clearing the halt requires an audited admin acknowledgement
with a justification. This supersedes the earlier "the run completes without it" wording, which would
have let deletions continue past an unexplained inconsistency.

`pending_delete` blobs are treated as unavailable by readers, so a stuck item is never served.
`GET /system/retention/runs` exposes run and item state.

### 4.5 Orphan sweeper
Reports files with no `evidence_blobs` row, and rows whose file is missing (`state='missing'`). It
**reports only**; it never deletes autonomously, and a `missing` row halts deletion as above.

## 5. Restoration

**Purge is final; the MVP has no restoration capability.** No undelete, no trash, no retained copy.
Restoration is possible only from an operator-managed backup that this repository does not automate
and whose existence the platform does not assume. The controlled flow
(`raw_restoration_requests`): admin requests with justification → second admin decides where dual
control is available → operator restores out-of-band → re-ingest **verifies `content_sha256` against
the surviving DB record** and refuses on mismatch → every step audited. Where no backup exists the
request is closed `unavailable`, which is the expected MVP outcome.

Provenance survives purge in all cases: hashes, adapter, rule id, timestamps and finding links
remain, so a finding resolves to *"evidence existed, hash X, purged at T by actor Y"*. A delivered
report never silently loses its chain.

## 6. Encryption at rest — assumptions and limits

No application-level encryption in the MVP. Host full-disk encryption is **assumed, not verified**;
`/system/capabilities` reports `evidence_encryption: "none (host FDE assumed, unverified)"` and the
report Limitations section states it. Protects against: theft of a powered-off disk. Does **not**
protect against: root or container escape on the running host, any process that can read the volume,
backup copies, misconfigured bind mounts, process memory, database dumps, or the host operator.
`SECRET_KEY`, `POSTGRES_PASSWORD`, `ZAP_API_KEY`, `REDACTION_HMAC_KEY` and the LLM key share the same
assumption and limits. Deferral is acceptable **because MVP evidence is synthetic only**; envelope
encryption + key management is required before any non-synthetic data is stored (open decision D13).

## 7. Test obligations

Shared blob: purging one of two referencing evidence rows must **not** unlink the file · pinned blob
skipped and counted · the crash-recovery matrix replayed at **every** boundary (invariant I12) · kill
the worker between unlink and row-null ⇒ reconciler completes the item and the row ends purged · kill
before any destructive step ⇒ plan resumes with nothing lost · unlink of an already-absent file
succeeds · file absent with **no** committed intent ⇒ `missing` + halt, never recorded as a purge ·
identity-check mismatch ⇒ no unlink + halt · a failed item blocks the next destructive run until
acknowledged · reference created concurrently with a purge (row lock serialises;
either skipped or blocked, never a dangling reference) · `analyst` denied raw access, `admin` allowed
with justification and an audit row · no bulk raw export route exists · retention keeps provenance
after purge and the finding still renders · orphan sweeper reports without deleting · restoration
with a mismatched hash refused · capabilities endpoint and report both state the encryption posture.
