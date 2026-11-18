# MVP Phase 5 — Findings, evidence, deterministic validation, CVSS

Baseline `92f5a0c`. Raw observations now become **defensible findings**: normalised, deduplicated,
evidence-backed, classified by deterministic rules, and carrying CVSS from a curated catalogue.
**Still no scan of the live target** — ZAP reports zero alerts, sites and messages.

## 1. What was built

| Area | Delivered |
|---|---|
| Catalogue | `vuln_catalogue`, 12 curated classes with CWE ids, CVSS v3.1 vectors and remediation. Human-maintained; the **only** default source of CVSS |
| Normalisation | pure `raw observation → NormalizedFinding`; versioned ZAP plugin→catalogue map; unmapped rules **kept** with a null catalogue key and surfaced separately |
| Identity | fingerprint with parameter **names in, values out** (decision D9); an evidence-class change re-opens identity; versioned so a change implies a migration |
| Evidence | redaction **on write**; unredacted original to a content-addressed blob store (atomic write, `0600`, dedup by digest); `redaction_report` recorded per item |
| Redaction | keyed **HMAC** correlation refs (`ref=hmac:v1:…`), never a plain digest of a secret; fails closed — an internal error replaces the whole value |
| Validation | pure rule packs over stored evidence only, producing all five states; every outcome records rule id, version, inputs and the evidence it used |
| Soundness | **negative evidence is suppressed under partial coverage** — "absent everywhere we looked" is meaningless if collection was truncated |
| CVSS | parse-and-validate from the catalogue; a malformed vector or out-of-range score is **refused**, not stored |
| Prioritisation | **deliberately absent**: `priority_score`, `priority_band`, `formula_version` stay null, and EPSS/KEV are null rather than estimated |
| API | findings list/summary/detail, evidence content (redacted; raw gated), validation history, analyst override, suppression, assessment revalidation |

## 2. Results — the engine discriminates

From the synthetic fixtures (13 ZAP-shaped alerts), **12 findings**:

| State | Count | Why |
|---|---|---|
| `confirmed` | 7 | header absent across complete coverage; evidence string located in the stored body; payload reflected **unencoded** in an HTML context |
| `false_positive` | 3 | a header claimed missing that the stored response **sets**; an evidence string **not** in the body; a payload reflected but **encoded** |
| `not_applicable` | 1 | a browser security header claimed on a JSON API endpoint |
| `candidate` | 1 | an unmapped scanner rule — kept and surfaced, never dropped |

Severity spread: 5 medium, 4 low, 2 high, 1 informational. CVSS attached from the catalogue
(e.g. CSP 5.0, reflected XSS 6.1, timestamp disclosure 3.7); entries without a published vector
carry **null**, not a guess.

## 3. The soundness property, demonstrated

Marking a job's coverage incomplete (as a truncated or cancelled scan does) and revalidating:

```
coverage_complete = true   ->  confirmed 7   false_positive 3   not_applicable 1   candidate 1
coverage_complete = false  ->  confirmed 3   false_positive 3   not_applicable 1   candidate 1
                                inconclusive 4
restored to true           ->  confirmed 7   (identical to the first run)
```

The 4 missing-header findings degrade `confirmed → inconclusive`; the false positives and the
reflected-XSS confirmation are untouched, because **presence** does not depend on coverage.
Revalidation created **0 new findings** — the pipeline is idempotent over unchanged inputs.

## 4. Invariants now implemented

**I6 — no finding becomes confirmed solely through LLM output.** A database CHECK rejects
`actor_kind='agent'` on `validation_events`; a trigger makes the table append-only, so a human
override **coexists** with the automated result rather than replacing it; a human event without a
justification is refused by a second CHECK. All four asserted against the live database.

**I7 — no referenced evidence blob is purged.** `delete_if_unreferenced` recounts active references
by query under a row lock and refuses while any remain (exercised against the real store: `REFUSED`,
never `DELETED`). A database trigger additionally refuses to create a blob reference while a purge is
in flight, which is what makes the pre-unlink recount durable.

**Invariant manifest corrected.** It previously claimed I1/I2/I3/I9/I14 were "pending M2" while real
tests existed, because `MILESTONE_STATE` was never advanced and the registry pointed at no modules.
The registry now uses the delivered phase labels (P1–P8), points at the real test files, and records
P1–P5 as landed: **10 of 14 invariants have real tests**; the 4 skips (I5, I10, I11, I12) are
genuinely unimplemented phases.

**I12 re-mapped honestly.** It covers scheduled *purge runs* (plan → intent → unlink → row → halt),
which the MVP defers (`RETENTION_ENABLED=false`). It now points at P8 rather than being marked done
on the strength of I7's deletion guard.

## 5. Suites

`net_verify` **115/115** · lab containment **exit 0** · `pytest tests/backend` **110 passed**
(1 skipped by design — see §6) · `tests/net` **56** · invariants **20 passed, 4 skipped** ·
`alembic check` clean · **0 failing**.

Evidence access control, verified end to end: analyst → `403`, admin without justification → `400`,
admin with justification → `200` **and audited**.

## 6. Defects found and fixed

| Defect | Consequence | Fix |
|---|---|---|
| **`.gitignore` had a bare `evidence/` pattern** which matched the source package `backend/app/evidence/` | the redaction and blob-store modules would have been **silently excluded from the repository** | runtime paths anchored (`/evidence/`, `/var/`, …) with a comment explaining why a bare directory name must never be used |
| **Fixture mode required a pinned target address**, so it depended on the lab being up | the fixture path — which exists precisely to work without the target — broke whenever the lab was down, and reported it as `adapter refused` | the spec carries its mode; a pinned address is required for `live` only, and the ZAP adapter refuses non-live work outright. Proven by completing a full assessment with findings while the lab was **down** |
| The request/response bytes were discarded at ingestion | no evidence, and validation had nothing to check against | the bytes go to the blob store and the raw observation records the blob ids, keeping unredacted material in exactly one place |
| `make db-migrate` used the migrations baked into the image | a freshly generated revision was invisible, and `alembic check` then disagreed with the database | the working tree is mounted; added `make db-check` |
| A `replace` without a count added blob columns to `ingestion_rejections` too | dead columns on a table whose whole point is that nothing was stored | removed before the migration was generated |
| The named evidence volume is root-owned | the first assessment failed with `PermissionError` (loudly, not silently) | `make evidence-init` grants the non-root app user the volume |
| The cancellation SLA test raced a one-poll mock | a **flaky safety test**, which is worse than an honest skip | it now requires `MOCK_FAULT=slow` and skips with instructions otherwise; `make test-cancellation` runs it deterministically (and needed `--force-recreate`, since compose ignores an env-value-only change) |

## 7. Limitations

1. **No live scan.** Findings come from hand-authored ZAP-shaped fixtures. Real alert volumes,
   fields and false-positive rates will differ.
2. **Rule coverage is partial** — five evidence classes. Anything else stays `candidate` with the gap
   recorded, which reads as under-reporting and is intentional.
3. **No prioritisation score**, by decision. Reports will show CVSS and severity only.
4. **Retention purge runs are not implemented** (`RETENTION_ENABLED=false`): the reference-aware
   deletion guard exists and is tested (I7), the scheduled run machinery and halt behaviour do not
   (I12, deferred to P8).
5. The reflected-unencoded heuristic is deliberately conservative; a real XSS corpus would exercise
   it far harder than two fixtures.
6. Evidence is not encrypted at rest (assumption B7); host FDE is assumed and unverified.

**Next: phase 6 — the AI analyst (redaction boundary stage 2, egress proxy use, bounded LangGraph,
citations) or phase 7 (dashboard + reports), whichever you want first.**
