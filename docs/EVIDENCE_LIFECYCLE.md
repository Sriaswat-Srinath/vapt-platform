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

### 4.2 Per-blob deletion protocol
```
BEGIN
  SELECT … FROM evidence_blobs WHERE id=:b FOR UPDATE          -- serialise against new references
  recount active references (computed, never a cached counter):
      evidence rows with blob_id=:b AND blob_purged_at IS NULL
    + unreleased evidence_pins with pins_blob=true on those rows
  IF count > 0 → item state 'skipped_pinned' / 'skipped_referenced'; COMMIT; next item
  state := 'pending_delete'
COMMIT
unlink(storage_path)            -- idempotent: absent file is success
  item state := 'unlinked'
BEGIN
  re-assert count == 0 ; evidence_blobs.state := 'purged', purged_at := now
  evidence.blob_purged_at := now for the referencing rows
  item state := 'row_nulled' → 'done'
COMMIT
```
**A blob is never unlinked while an active reference exists** — three independent guards: the FK, the
`FOR UPDATE` row lock with an in-transaction recount, and the post-unlink re-assertion.

### 4.3 Ordering is chosen for a safe failure mode
Unlink **before** nulling the DB reference. A crash between the two leaves *"the row references a
file that is gone"* — detectable and repairable. The reverse order would leave *"the row says purged
while the secret is still on disk"* — a silent retention failure. Correctness of the secret-removal
guarantee beats bookkeeping tidiness.

### 4.4 Interrupted-purge recovery
Every step is idempotent and keyed by `(run_id, target_kind, target_id)`. A worker-startup reconciler
finds `running` runs with a stale lease, marks them `interrupted`, and resumes item by item, audited.
Auto-resume is deliberate — a half-finished purge is not a state to sit in. An item failing twice is
marked `failed` and reported; the run completes without it rather than blocking indefinitely.
`pending_delete` blobs are treated as unavailable by readers, so a stuck item is never served.
`GET /system/retention/runs` exposes run and item state.

### 4.5 Orphan sweeper
Reports files with no `evidence_blobs` row, and rows whose file is missing (`state='missing'`). It
**reports only**; it never deletes autonomously.

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
skipped and counted · kill the worker between unlink and row-null ⇒ reconciler completes the item and
the row ends purged · kill before any destructive step ⇒ plan resumes with nothing lost · unlink of
an already-absent file succeeds · reference created concurrently with a purge (row lock serialises;
either skipped or blocked, never a dangling reference) · `analyst` denied raw access, `admin` allowed
with justification and an audit row · no bulk raw export route exists · retention keeps provenance
after purge and the finding still renders · orphan sweeper reports without deleting · restoration
with a mismatched hash refused · capabilities endpoint and report both state the encryption posture.
