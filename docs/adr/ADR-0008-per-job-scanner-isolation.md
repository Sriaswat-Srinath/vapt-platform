# ADR-0008: Per-job scanner isolation via a long-lived ZAP daemon with per-job contexts

- Status: Accepted (2026-11-12); **amended R2 (2026-11-12)** — revisit at M11
- Relates to: D4, ADR-0005

## Context
Two ways to isolate scan jobs from one another: a container per job (strongest blast-radius
isolation, trivially correct teardown, slow start, more orchestration — and orchestration would mean
either a Docker socket, which is forbidden, or a privileged side-car) or one long-lived daemon with
per-job contexts and sessions (fast, simple, but state can bleed between jobs through the shared
session, the sites tree, the passive-scan queue and the alert store).

## Decision
Long-lived ZAP daemon, with **per-job isolation implemented explicitly** rather than assumed:

1. **One ZAP context per job**, named `job-<job_id>`, carrying include regexes derived from the
   asset's scope rules and exclude regexes from `profile.excluded_path_patterns`.
2. **Session isolation**: each job begins with `core/action/newSession` (so the sites tree, message
   store and alert store start empty) and the adapter asserts the alert count is zero before starting.
   Jobs on the same asset are serialised by a Postgres advisory lock, so no two jobs share a session.
3. **Scoped collection**: alerts are retrieved filtered by `baseurl` and cross-checked against the
   job's pinned IP/host/port set; any alert whose URL is out of scope is rejected and audited
   (`findings` never receives it), which also catches leakage from a stale session.
4. **Deterministic teardown** in a `finally` path: `stopScan` → confirm idle → `removeContext` →
   `newSession` → assert empty. `teardown()` failures mark the job `failed` with
   `stop_reason='teardown_unconfirmed'` and set a daemon-dirty flag that blocks new jobs until an
   admin runs `/system/scanner/reset`.
5. **Handle persistence**: ZAP context and scan ids live in `scan_jobs.adapter_handle`, so a worker
   restart re-attaches or explicitly fails the job instead of orphaning daemon state.
6. **Process hardening** (unchanged from `SAFETY.md` L2): non-root, read-only rootfs + tmpfs workdir,
   `cap_drop: ALL`, `no-new-privileges`, pid/memory/CPU limits, `lab` network only, API key required,
   **no Docker socket mounted — ever**.

## Consequences
+ No Docker socket and no privileged orchestration, satisfying the brief's hard prohibition.
+ Fast job start; no image pull or daemon boot per job.
+ Cross-job contamination is detectable rather than merely unlikely: the empty-session assertion and
  the out-of-scope alert rejection both fail loudly.
− A ZAP crash affects the daemon, not just one job; the reconciler must fail in-flight jobs cleanly.
− Isolation correctness now depends on our teardown code. Mitigation: a dedicated M5 test that runs
  two consecutive jobs on different seed sets and asserts job B sees none of job A's alerts, sites or
  messages; and the dirty-flag gate above.
− If session bleed is observed in M5/M11 despite this, the fallback is a container per job driven by a
  rootless supervisor (not a socket mount). That change requires approval per the no-silent-change
  rule.

---

## Amendment R2 (2026-11-12) — global daemon serialisation

### Why the original was insufficient
The decision above relied on a **per-asset** advisory lock. That is wrong for a shared daemon:
`core/action/newSession`, `core/action/newSession`-adjacent state (sites tree, message store, alert
store), the passive-scan queue and the global scan-policy selection are **daemon-global operations**.
A job on asset A calling `newSession` would destroy the session of a concurrent job on asset B, and
B's alert collection would silently return a partial or empty set — a correctness and evidence-
integrity failure, not merely a performance one. The per-asset lock cannot prevent this because the
two jobs hold different lock keys.

### Decision (MVP)
1. **One active ZAP job globally.** `ZAP_MAX_CONCURRENT_JOBS = 1`, clamped in code — a larger
   configured value is rejected at startup, not silently honoured.
2. **One context per job**, unchanged.
3. **A global daemon lock held across the complete session lifecycle**, not just around
   `newSession`:

   ```
   acquire global daemon lease  ──┐
     newSession                   │
     assert stores empty          │  the ENTIRE lifecycle is inside the lock;
     create context job-<id>      │  no other job may touch the daemon
     spider / passive / active    │
     collect (paginated)          │
   finally: teardown + confirm ───┘
   release lease
   ```

   Implementation: a session-level `pg_advisory_lock` on a fixed key (`'vapt:zap:daemon'`) taken on a
   dedicated DB connection held for the job's duration, **plus** a `scanner_daemon_leases` row
   carrying holder, `acquired_at`, `heartbeat_at`, `expires_at` and job id. The advisory lock is the
   mutex; the lease row makes ownership observable, gives crash detection, and survives for forensics.
4. **Per-asset concurrency controls retained** — the per-asset advisory lock and
   `MAX_CONCURRENT_JOBS_PER_ASSET` stay in place. They are now a second, narrower control, not the
   isolation mechanism. `MAX_CONCURRENT_JOBS_GLOBAL` continues to bound non-ZAP work.
5. **Unconfirmed teardown ⇒ daemon dirty.** Any of: `stopScan` error, scanner not confirmed idle,
   `removeContext` error, `newSession` error, or post-teardown stores not empty.
6. **Dirty state blocks every subsequent scanner job**, across all assets and all profiles, until an
   admin runs `POST /system/scanner/reset` (which itself takes the global lease, re-initialises the
   daemon, verifies empty stores, and is audited).
7. **Crash recovery is fail-safe.** If a worker dies, the advisory lock releases with its connection
   while the lease row remains. The next acquirer that finds a lease row whose advisory lock is
   unheld, or whose heartbeat is stale, **marks the daemon dirty** — the previous job's teardown is
   unproven, so daemon state is unknown and must not be trusted. Recovery is explicit admin action,
   never an assumption.
8. **No concurrent ZAP sessions** are introduced until isolation is demonstrated by dedicated tests.
   Raising `ZAP_MAX_CONCURRENT_JOBS` above 1 is out of scope for the MVP and requires a superseding
   ADR, not a configuration change.

### Scope of the lock
The global lease applies to the **ZAP adapter only**, because the hazard is shared daemon state. The
`mock` adapter has no shared daemon and is not serialised globally, so CI retains parallelism. A
future adapter declares whether it needs the global lease via
`Capabilities.requires_exclusive_daemon`.

### Preflight
A new gate, **gate 13 `scanner_daemon_available`**, denies when the adapter requires the exclusive
daemon and the daemon is dirty, or a live lease is held, or a lease is stale-and-unreconciled.
Denials are persisted in the `ScopeDecision` like any other gate.

### Consequences
+ The real hazard — a global operation inside a per-asset lock — is removed rather than narrowed.
+ Unknown daemon state is always resolved to "dirty", so evidence integrity is never assumed.
+ The lease row makes "who holds the scanner, since when" answerable during an incident.
− **Throughput ceiling: one ZAP job at a time, platform-wide.** Accepted for the MVP; queueing is
  visible in `scan_jobs.state='queued'` and the UI shows the queue position.
− A crashed worker costs an admin reset rather than auto-recovering. Deliberate: the alternative is
  trusting unverified daemon state.
− Two locks now exist (global daemon, per-asset). Their distinct purposes are documented in
  `SCANNER_LIFECYCLE.md` so the narrower one is never mistaken for the isolation control again.
