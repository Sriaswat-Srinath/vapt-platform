# ADR-0011: Evidence retention and access controls

- Status: Accepted (2026-11-12)
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
  `blob_path = NULL` and `blob_purged_at` set, so provenance (hashes, adapter, rule id) survives the
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
