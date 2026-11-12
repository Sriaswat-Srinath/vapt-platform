# Scanner Lifecycle (ZAP) — locks, states and teardown

Normative for M5. Implements ADR-0008 + R2. The hazard being managed: **`newSession`, the sites tree,
the message store, the alert store, the passive-scan queue and the active scan policy are all
daemon-global**, so any concurrency between ZAP jobs corrupts evidence rather than merely slowing it.

## 1. Two locks, two different purposes

| Lock | Key | Scope | Purpose | Held for |
|---|---|---|---|---|
| **Global daemon lease** | `pg_advisory_lock('vapt:zap:daemon')` + `scanner_daemon_leases` row | the whole platform | **the isolation control** — guarantees one ZAP job exists at a time | the complete session lifecycle, acquire → release |
| Per-asset lock | `pg_advisory_lock('vapt:asset:<asset_id>')` | one asset | prevents double-scanning one asset; bounds non-ZAP adapters | one job |

The per-asset lock is **not** an isolation control for a shared daemon and must never again be
treated as one. `MAX_CONCURRENT_JOBS_PER_ASSET` and `MAX_CONCURRENT_JOBS_GLOBAL` remain as budget
ceilings; `ZAP_MAX_CONCURRENT_JOBS = 1` is clamped in code and a larger configured value is rejected
at startup.

Adapters declare their need: `Capabilities.requires_exclusive_daemon`. `zap` → `true`; `mock` →
`false` (no shared daemon, so CI keeps its parallelism).

## 2. Lifecycle

```
                  ┌──────────────────────────────────────────────────────────┐
                  │ preflight gates 1–13 (13 = scanner_daemon_available)     │
                  └───────────────────────────┬──────────────────────────────┘
                                              ▼
   acquire global daemon lease  ── fail ──▶ job stays `queued` (requeue w/ backoff)
   (advisory lock on a dedicated
    connection + lease row,
    heartbeat every 10s)
          │
          ▼
   ┌──────────────────────── inside the lease ───────────────────────────────┐
   │ 1. health: /JSON/core/view/version                                      │
   │ 2. core/action/newSession (name=job-<id>, overwrite)                    │
   │ 3. ASSERT stores empty: alerts==0, sites==[], messages==0               │
   │      └─ not empty ⇒ daemon dirty, job `failed`                          │
   │ 4. context create `job-<id>`; include regexes from scope rules;         │
   │    exclude regexes from profile.excluded_path_patterns                  │
   │ 5. apply budgets: per-host delay, thread count, timeouts; load pinned   │
   │    scan policy; apply rule denylist; active rules OFF unless permitted  │
   │ 6. phases: spider → passive drain → [active] → collect (paginated,      │
   │    baseurl-filtered, cross-checked against pinned IP/host/port)         │
   │ 7. persist raw_observations (verbatim + hashes) as they arrive          │
   └────────────────────────────────┬────────────────────────────────────────┘
                                    ▼  (always, via finally)
   ┌──────────────────────── teardown, still inside the lease ───────────────┐
   │ T1 stopScan(all)        T2 confirm idle (poll, bounded)                 │
   │ T3 removeContext        T4 newSession (clean)                           │
   │ T5 ASSERT stores empty  T6 teardown_confirmed_at = now                  │
   │   any failure ⇒ daemon_dirty = true, stop_reason='teardown_unconfirmed' │
   └────────────────────────────────┬────────────────────────────────────────┘
                                    ▼
                        release lease (row closed, advisory lock released)
```

## 3. Job state machine

```
queued ─▶ preflight ─▶ running ─▶ (pausing) ─▶ paused ─▶ running
                          │  │                    │
                          │  └─▶ cancelling ─▶ cancelled
                          │
                          ├─▶ completed            (stop_reason: ok | budget_exhausted)
                          ├─▶ failed               (error | teardown_unconfirmed |
                          │                         cancel_unconfirmed | session_dirty)
                          └─▶ blocked              (gate denial recorded pre-start)
```
Cancellation and pause requests are polled at every phase boundary and between collection pages.
A cancel that the adapter cannot confirm ⇒ `failed` + `cancel_unconfirmed` + daemon dirty.
Phases 4–6 of the pipeline (normalise, validate, score) still run on whatever was collected; the
report marks coverage partial.

## 4. Dirty-daemon semantics

Set dirty on: non-empty stores at step 3 or T5 · any teardown step failing · unconfirmed cancel ·
an acquirer finding a stale or unheld lease (previous teardown unproven ⇒ state unknown ⇒ untrusted).

While dirty: **gate 13 denies every job requiring the exclusive daemon, on every asset, for every
profile.** Recovery is only `POST /system/scanner/reset` (admin): takes the lease, re-initialises,
asserts empty stores, clears the flag, audit-logs the whole sequence. There is no automatic
self-clearing and no configuration override.

## 5. Crash recovery

The advisory lock dies with its connection; the lease row does not. On worker startup, and on every
acquisition attempt, the reconciler classifies:

| Observed | Interpretation | Action |
|---|---|---|
| no lease row, lock free | clean | acquire |
| lease row + lock held + fresh heartbeat | another live job | stay `queued` |
| lease row, lock free (or heartbeat stale) | **teardown unproven** | mark daemon dirty, close the lease as `abandoned`, fail the orphaned job, require admin reset |
| lease row for a job already terminal | stale bookkeeping | close lease, mark dirty (daemon state unverified) |

`scan_jobs.adapter_handle` persists ZAP context/scan ids so an orphaned job is identifiable and
explicitly failed rather than silently abandoned.

## 6. Test obligations (M5)

Cross-job contamination (two consecutive jobs, different seed sets — job B must see none of job A's
alerts, sites or messages) · concurrent submission (job B waits; `newSession` never runs while A holds
the lease; asserted by lease timeline, not by timing) · non-empty stores at entry ⇒ dirty + fail ·
each teardown step failing in turn ⇒ dirty + `teardown_unconfirmed` + subsequent jobs on a *different*
asset denied at gate 13 · killed worker mid-scan ⇒ next acquirer marks dirty, orphan job failed,
reset restores service · `ZAP_MAX_CONCURRENT_JOBS=2` ⇒ startup refused · unconfirmed cancel ⇒ failed +
dirty · mock adapter unaffected by the global lease (parallel jobs still run).
