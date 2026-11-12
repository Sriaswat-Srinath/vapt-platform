# Decision Log — approved 2026-11-12

Supersedes `OPEN_DECISIONS.md` (retained for history). These decisions are **binding**. Per
`CLAUDE.md` rule 16 and `SECURITY_ASSUMPTIONS.md` §E, if one becomes technically infeasible,
implementation stops and the trade-off is presented for approval before anything changes.

| # | Decision | Status | Modifications required by the owner |
|---|---|---|---|
| D1 | Celery + Redis for async jobs | **Approved** | — |
| D2 | `analyst` / `approver` / `admin` with hashed API tokens | **Approved** | Approval events record **both** participants' identities. Two accounts held by one person are **not** dual control; where only one human operates the environment this is documented explicitly and simulated approval is never represented as independent human approval → ADR-0009 |
| D3 | LLM egress from the api/agent component only | **Approved w/ modifications** | Exactly one explicitly configured provider; scanner workers airgapped; credentials from env vars, never committed; **credentials, tokens, personal data and sensitive raw evidence redacted before anything is sent to the LLM**; provider and model configurable → ADR-0010, `CONFIGURATION.md` |
| D4 | Long-lived ZAP daemon with per-job contexts | **Approved** | Explicit context cleanup, session isolation and job teardown; cross-job contamination prevented **and detected** → ADR-0008 |
| D5 | WeasyPrint for PDF | **Approved** | HTML and JSON reports remain available independently of PDF generation |
| D6 | Authenticated scanning | **Deferred** | Unauthenticated discovery and scanning initially; authentication entry points still recorded in the attack-surface inventory |
| D7 | Active scanning | **Approved w/ restrictions** | Separate, explicitly controlled capability; **disabled by default**; requires an approved profile + explicit target scope + **two independent human approvals**; if genuine dual control is unavailable, intrusive profiles stay disabled; local mock applications only → ADR-0009, gate 7 |
| D8 | EPSS/KEV as dated offline snapshots | **Approved** | Missing intelligence yields **NULL**, never a fabricated estimate |
| D9 | Fingerprint: parameter names in, values out | **Approved** | Per `SCANNER_INTEGRATION.md` §5 |
| D10 | Analyst override of validation state | **Approved** | Mandatory justification, timestamp, actor identity, immutable audit event; **the original automated validation result is preserved** (append-only `validation_events`, never overwritten) |
| D11 | Local volume-backed blob store, references in PostgreSQL | **Approved** | Access controls + configurable retention; **synthetic test evidence only in the MVP** → ADR-0011 |
| D12 | React Query + generated OpenAPI types | **Approved** | — |

## Confirmations

| # | Item | Resolution |
|---|---|---|
| 1 | Authorisation document | `lab/authorisation/MOCK-WEB-001.md` accepted. It authorises testing **only** against the locally hosted synthetic Juice Shop instance and explicitly grants **no** authorisation over any real Brakes India infrastructure. Drafted unsigned; an operator must complete and sign it, after which its SHA-256 is recorded in the scope grant |
| 2 | Mock asset | HTTP, container port `3000`, published host port `3000`, bound **exclusively to `127.0.0.1`** (startup validation refuses any non-loopback publish) |
| 3 | Network | `LAB_SUBNET=172.30.10.0/24`. Conflict check performed 2026-11-12: free (host Docker networks occupy `172.17.0.0/16`, `172.18.0.0/16`, `172.19.0.0/16`; host LAN `192.168.1.0/24`); re-verified by `make lab-check` before every `lab-up`. **Subnet membership is not authorisation** — the exact registered host and port allowlist is enforced in addition (gates 9–10) |
| 4 | Hostname | `shop.brakes-vapt.test` is a Docker network alias resolvable only inside `vapt_lab`. Workstation access is `http://127.0.0.1:3000`. **No hosts-file entry will be added** |
| 5 | Approver | Role and approval infrastructure built; `DUAL_CONTROL_AVAILABLE` defaults false and cannot be honoured without ≥2 attested, distinct, active identities. Intrusive scanning stays disabled until then, and the limitation appears in `/system/capabilities`, the UI and every report |
| 6 | LLM | Provider and model configurable; credentials read from env vars; provider/model/credential referenced in exactly one module (`agent/llm/provider.py`) and nowhere else |
| 7 | Git | Repository initialised; M0 architecture, plan and ADRs committed before M1. `.gitignore` excludes `.env*` (except `.env.example`), secrets, evidence, blob store, DB volumes, reports and scanner output |

## Architectural records

ADR-0001 modular monolith · ADR-0002 immutable raw observations · ADR-0003 deterministic validation ·
ADR-0004 CVSS separate from priority · ADR-0005 network egress denial primary · ADR-0006
resolve-once-and-pin · ADR-0007 agent proposes, humans decide · **ADR-0008 per-job scanner
isolation** · **ADR-0009 dual-control limits in a single-operator environment** · **ADR-0010 LLM
evidence redaction** · **ADR-0011 evidence retention and access controls**.

---

## Round 2 clarifications — reviewed and accepted 2026-11-12

ADR-0008…0011 were reviewed by the owner and accepted subject to the clarifications below. All are
now binding and are reflected in the ADR amendments, the schema proposal (`DATA_MODEL.md` §11) and
the new lifecycle documents.

| Ref | Clarification | Where implemented |
|---|---|---|
| R2-1 | **Global** PostgreSQL advisory lock for the ZAP daemon — the per-asset lock is insufficient because `newSession` is a daemon-global operation that would corrupt a concurrent job on a *different* asset | ADR-0008 R2; `SCANNER_LIFECYCLE.md` §1–2 |
| R2-2 | MVP: one active ZAP job globally; one context per job; global lease held across the **complete** session lifecycle; per-asset controls retained as a narrower budget control | ADR-0008 R2 §1–4; `ZAP_MAX_CONCURRENT_JOBS=1` clamped in code |
| R2-3 | Any unconfirmed teardown marks the daemon dirty; dirty state blocks **all** subsequent scanner jobs until an audited admin reset | ADR-0008 R2 §5–7; new preflight **gate 13** |
| R2-4 | No concurrent ZAP sessions until isolation is demonstrated by dedicated tests; raising the limit needs a superseding ADR, not a config change | ADR-0008 R2 §8; `SCANNER_LIFECYCLE.md` §6 |
| R2-5 | Approvals are **invalidated** when an identity is revoked, deactivated or loses attestation; dependent in-flight jobs stop at the next cancellation checkpoint, bounded by `CANCELLATION_SLA_SECONDS` (R3-5); invalidation is not reversed by re-activation | ADR-0009 R2 §7; `approval_state += invalidated`; `identity_events` |
| R2-6 | Configuration cannot bypass startup verification: `DUAL_CONTROL_AVAILABLE` is an input, the effective value is **computed** at startup *and* at every gate 7 evaluation; no column, flag or field can set it directly | ADR-0009 R2 §8; `CONFIGURATION.md` §R2 |
| R2-7 | Five-case identity test matrix; only two distinct, active, attested identities may satisfy the precondition, and **all other gates still apply** | ADR-0009 R2 §9 |
| R2-8 | Redaction coverage across JSON (incl. nested arrays), URL query parameters, HTML forms, multipart, XML, exception messages, tool errors and stack traces, and recognisable encoded credentials | ADR-0010 R2 §9; `REDACTION_DATAFLOW.md` §7 |
| R2-9 | **Keyed HMAC identifiers** for secret-value correlation, replacing plain SHA-256 prefixes (which were brute-forceable for low-entropy secrets and therefore leaked the value) | ADR-0010 R2 §7 |
| R2-10 | Content-integrity hashes preserved **separately** and never placed in an LLM-bound payload | ADR-0010 R2 §8; `REDACTION_DATAFLOW.md` §4 |
| R2-11 | The agent must have no direct **or indirect** path to raw evidence — ten paths enumerated and each closed with a test | ADR-0010 R2 §10 |
| R2-12 | Before retention is implemented: reference-aware blob deletion, interrupted-purge recovery, report pinning semantics, raw restoration policy, encryption-at-rest assumptions and limits | ADR-0011 R2 §7–11; `EVIDENCE_LIFECYCLE.md` |
| R2-13 | A blob must not be deleted while any active evidence reference requires it | ADR-0011 R2 §7; three independent guards (FK, `FOR UPDATE` + in-transaction recount, post-unlink assertion) |
| R2-14 | `MOCK-WEB-001.md` is an unsigned draft: do not sign it, do not modify its signature fields, do not auto-activate a ScopeGrant; **scanner execution remains denied until it is signed and verified** | `scope_grants.document_state` + CHECK `state<>'active' OR document_state='signed_verified'` (`DATA_MODEL.md` §11.4); gate 5 re-verifies; the file is untouched since its unsigned commit |
| R2-15 | `CONFIGURATION.md` is the configuration baseline and `SECURITY_ASSUMPTIONS.md` the security/residual-risk baseline; safety defaults are not to be changed silently | both carry an R2 baseline notice; any change requires an approved ADR |

### Consequences accepted with these clarifications
- **Throughput:** one ZAP job at a time platform-wide; queue depth is visible in the UI.
- **Availability:** a crashed worker requires an audited admin scanner reset rather than
  auto-recovery, because unverified daemon state must not be trusted.
- **Correlation:** rotating `REDACTION_HMAC_KEY` ends correlation with pre-rotation refs; retaining
  correlation across rotation would require keeping the secrets, which is refused.
- **Reports do not extend secret lifetime:** `pins_blob` defaults to false, so report generation pins
  redacted evidence only.
- **Purge is final:** no restoration capability exists in the MVP; the request flow exists so that
  any future restoration is controlled, verified and audited rather than ad hoc.

---

## Round 3 — clarifications accepted 2026-11-12

D13–D18 approved with the proposed defaults. The expanded invariant suite **I1–I14** and the
**invariant manifest test** are approved and specified in [INVARIANTS.md](INVARIANTS.md).

| Ref | Clarification | Where implemented |
|---|---|---|
| R3-1 | Synthetic-only enforcement must rest on asset provenance and ingestion controls, not a database label | ADR-0011 R3 §13; `SAFETY.md` §8.1; `DATA_MODEL.md` §12.3; assumptions A19–A20, **B8** |
| R3-2 | Purge must distinguish PostgreSQL transactions from filesystem operations, which cannot be atomic together: committed-intent state machine, locking, reference recount, unlink verification, database update, crash recovery | ADR-0011 R3 §12–12.5; `EVIDENCE_LIFECYCLE.md` §4; `SAFETY.md` §8.5; A21 |
| R3-3 | An unresolved purge inconsistency must block further deletion (corrects the R2 "run completes without it" wording) | `retention_state.halted`; `RETENTION_HALT_ON_INCONSISTENCY` not disableable; invariant I12 |
| R3-4 | HMAC key management: env-only key material, key id + algorithm recorded per ref, no key retention for correlation, audited rotation, integrity hashes unaffected; key must not appear in logs, config dumps, exceptions or prompts | ADR-0010 R3; `redaction_key_state` (KCV only, never the key); invariant I11; A25 |
| R3-5 | Bounded cancellation latency with a defined maximum, not an indefinite wait for a phase to finish | ADR-0008 R3 §14; `CANCELLATION_SLA_SECONDS=120`; invariant I13; A24 |
| R3-6 | ZAP daemon crash: fail the job, mark dirty, verify what can be verified, require reset, preserve partial observations without confirming incomplete findings | ADR-0008 R3 §12–13; `coverage_complete`; A23, **B9** |
| R3-7 | The application cannot restart Docker containers (socket prohibited); the reset endpoint must verify daemon identity and health and must not clear the dirty flag without successful verification; the operator-performed restart must be documented | ADR-0008 R3 §9–11; `SAFETY.md` §8.2; `scanner_resets`; `CONFIGURATION.md` R3; A22; limitation 18 |
| R3-8 | M1 boundary confirmed: builds and proves the lab; no production or active scanning, no real infrastructure, no signed authorisation, no full application; completable with scanner execution disabled | `M1_ACCEPTANCE.md` §5–6 |

---

## Round 4 — MVP re-scope (2026-11-12)

The owner's recommendation (`MVP_SCOPE.md`) is adopted: single asset, single scanner,
human-supervised, one bounded agent. Milestones re-sequenced (`ROADMAP.md` v2); invariant milestone
mappings updated accordingly; the 13 milestone-aware skips are unchanged in count.

| Ref | Decision | Status |
|---|---|---|
| R4-1 | Defer Nuclei, priority formula, EPSS/KEV, multi-agent, vector DB, k8s, authenticated scanning, extra targets, retention purge runs, restoration flow | adopted; schema retained where evidence integrity depends on it |
| R4-2 | Adaptive test selection = deterministic surface→candidate matrix (L2) + agent ranking/explanation (L3) + human acceptance + full gate chain | adopted (consistent with ADR-0007) |
| R4-3 | Preflight gate chain, grants, approvals and identities move into v2 **M2** | adopted |
| R4-4 | **Active/injection tests in the demonstration** | **OPEN — owner ruling required** (`MVP_SCOPE.md` §4: option A two humans / option B passive-execute + active proposed-and-denied; C refused) |
| R4-5 | M1.5 network corrections precede M2 | plan written (`M1_5_PLAN.md`), pending approval |
| R4-6 | D19–D23 ratified with conditions | implemented, commit `9c988ba` |
