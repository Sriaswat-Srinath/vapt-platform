# MVP Phase 4 — Scanner adapters, raw observations, daemon isolation

Baseline `7506193`. A full assessment lifecycle now runs end to end and stores
provenance-carrying raw observations. **No scan of the live target has happened**: the authorisation
document is unsigned, so `live` assessments are denied at gate 1 and ZAP reports zero alerts, zero
sites and zero messages.

## 1. What was built

| Area | Delivered |
|---|---|
| Adapter contract | `app/scanners/base.py` — `Capabilities`, `ScanJobSpec`, `ScannerHandle`, `ScannerProgress`, `RawObservation` (content-addressed hashes), `CancelResult`. Adapters never write findings; `cancel()`/`teardown()` must *confirm* |
| Mock adapter (default) | replays hand-authored ZAP-shaped fixtures with **no network connection at all**, plus fault injection (`slow`, `no_stop`, `dirty`, `malformed`) so the failure paths are testable |
| ZAP adapter | real REST client and full per-job lifecycle: `newSession` → assert stores empty → context `job-<id>` with include/exclude regexes → budgets → spider → passive drain → baseurl-filtered collect → teardown → assert empty. **Active scanning is deliberately not implemented** — the adapter refuses active/intrusive profiles itself |
| Global daemon lease | `app/worker/daemon_lease.py` — session-level advisory lock on a dedicated connection, held across the entire session lifecycle, plus an observable lease row with heartbeat. A **partial unique index** enforces one `held` lease per adapter in the database |
| Raw observations | immutable (database trigger blocks UPDATE/DELETE), with payload/request/response SHA-256 and the pinned peer address |
| Ingestion rejection | an observation about any host other than the registered asset is **rejected and recorded**, never stored |
| Job lifecycle | queued → preflight → running (spider/passive/collect) → completed, with an event timeline, bounded cancellation, and teardown always attempted in a `finally` |
| Reset | verification-gated R2–R7, **delegated to the worker** (§3), with an audited record per attempt |

## 2. Fixture mode: how the pipeline is demonstrable without authorisation

Mirrors phase 3 exactly. `mode` is recorded on every job and every decision:

| Mode | Contact | Gates |
|---|---|---|
| `fixture` | **none** | the non-execution gates still apply (asset registered, `mock_lab`, scope rules, concurrency, no conflicting job) |
| `live` | the authorised target | all 13 |

The distinction lives **inside the pure policy**, not scattered through services, and it is not a
relaxation: the execution gates are marked *not applicable in fixture mode: no network contact is
made* on the decision record, and three independent checks refuse to let fixture mode touch anything
— the API refuses a non-mock adapter, the worker re-checks it, and the adapter itself refuses a spec
without an allow decision and a pinned address.

## 3. The reset had to move to the worker

`POST /system/scanner/reset?adapter=zap` originally ran in the API — but **the API has no route to
`vapt_lab` by design**, so it could not verify the daemon and would have reported
`requires_operator_restart` for a perfectly healthy ZAP. The API now records the request and
delegates; the worker performs R2–R7 and clears the flag only on a full pass. Verified against real
ZAP 2.17.0:

```
R2 pass=True version=2.17.0          R5 pass=True alerts=0 sites=0 messages=0
R4 pass=True newSession              R6 pass=True context create/read/remove
                                     R7 pass=True marker=vapt-instance-...
cleared_dirty=True  failing_step=None
```

## 4. Results

**Assessment lifecycle** (fixture mode, `requests_made=0`):

```
queued     preflight  job accepted after an allow ScopeDecision
preflight  preflight  worker claimed the job
running    preflight  adapter needs no shared session
running    spider     scan started
running    collect    collecting observations
completed  done       stored 6 observations, rejected 1 out-of-scope
completed  done       teardown confirmed: mock session discarded; stores empty
```

Six observations stored with `payload`/`request`/`response` SHA-256; **one rejected at ingestion**
(`host_mismatch`, `cdn.example.com`) and absent from storage.

**Measured cancellation:** request → terminal in **1.6 s** (SLA 120 s), `state=cancelled`,
`coverage_complete=false`, teardown still confirmed.

**Invariants now implemented:** **I8** — a dirty daemon denies gate 13 on every asset and profile,
an analyst cannot clear it (403), and only a verified reset clears it. **I13** — cancellation reaches
a terminal state within `CANCELLATION_SLA_SECONDS`, measured against the running worker.

**Suites:** `net_verify` **115/115** (2 new probes) · lab containment **exit 0** ·
`pytest tests/backend` **78** · `tests/net` **56** · `tests/lab` **62** ·
invariants **11 passed, 13 milestone-aware skips** · **0 failing**.

**Boundary re-verified:** live assessment denied at `scanner_execution_enabled`; ZAP stores empty;
no active or spider scans; `SCANNER_EXECUTION_ENABLED`, `ZAP_ADAPTER_ENABLED`, `ACTIVE_SCAN_ENABLED`,
`DUAL_CONTROL_AVAILABLE` all `false`; authorisation document untouched.

## 5. Defects found and fixed

| Defect | Consequence | Fix |
|---|---|---|
| **Cancellation was never observed.** `session.get()` returns the cached instance from the identity map, so the worker never saw a cancel committed by the API | cancellation silently did nothing — the job ran to completion | read the flag as a column with the transaction ended first; applied to discovery too. Found only by *measuring* a cancellation rather than asserting the code path |
| **The worker counted itself** in the in-flight total when re-evaluating its own job | every job blocked itself at gate 12 | `exclude_job_id` through the snapshot builder |
| **Autogenerate proposed dropping the one-held-lease index** (raw SQL is invisible to model metadata) | would have silently removed the database-level exclusivity guarantee | removed from the migration and `include_object` in `env.py` so it cannot recur; `alembic check` is clean |
| The migration also failed on a `NOT NULL` column with no server default | — | `server_default="live"` plus a CHECK constraint |
| Daemon flags had Python-side defaults only | an operator inserting a recovery row by hand hits a `NOT NULL` error | server defaults added (`c5000000srvdef`) |
| `ZAP_BASE_URL=""` (an empty env var) overrode the default | confusing client error instead of a clear one | fall back on blank as well as absent; refuse a URL without a scheme |
| **The lab probe client and the daemon-state script both used `172.30.10.30` — the worker's lab address since phase 3** | `I9a` failed and 10 lab tests broke | moved to `LAB_CLIENT_IP` (`.39`), still inside the ZAP api-addrs allowlist |
| `NET-C:worker` flagged the ZAP control key as a credential leak | a necessary credential looked like a violation | the ZAP *control* key is excluded and asserted positively (`NET-C:worker:zap-key`), while a new `NET-C:api:no-zap-key` proves the API holds no scanner credential |
| A phase-2 test asserted "no job rows for a denied request", which fixture jobs legitimately break | — | assertion sharpened to the real property: **no live assessment has ever executed, and no live job has stored an observation** |

## 6. Limitations

1. **The ZAP adapter's scanning path has never run.** Its *control plane* is verified against real
   ZAP 2.17.0 (version, session, empty-store assertion, context create/remove, idle check, teardown).
   Spider, passive drain and collect are implemented and unit-tested against fixtures but have not
   touched the target.
2. **Active scanning is not implemented at all**, by choice. Gate 7 would deny it, and the adapter
   refuses it independently.
3. Fixtures are hand-authored ZAP shapes, not captured output; real alert volumes and fields will
   differ.
4. The global lease is exercised by the database index and by unit tests; **two concurrent real ZAP
   jobs have not been raced**, because no ZAP job has run.
5. `coverage_complete=false` is recorded for cancelled and budget-exhausted jobs, but nothing
   consumes it yet — negative-evidence suppression belongs to phase 5's validation engine.
6. No findings yet: observations are raw. Normalisation, deduplication, validation and CVSS are
   phase 5.

**Next: phase 5 — normalisation with fingerprint/dedup, evidence with redaction, the deterministic
validation engine, and CVSS from the curated catalogue.**
