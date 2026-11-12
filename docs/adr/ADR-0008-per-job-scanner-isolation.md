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

---

## Amendment R3 (2026-11-12) — daemon crash handling, reset limits, bounded cancellation

### 9. The application cannot restart containers — and must not pretend to

Docker socket access is **permanently prohibited** (§6, and the brief's hard requirement). The
platform therefore has **no capability to start, stop, restart or recreate the ZAP container**, and no
code path attempts it. Every recovery mechanism below operates *inside* a running daemon over its
REST API, or else escalates to the operator.

The lab compose sets ZAP **`restart: "no"`** deliberately: a crashed daemon must stay down rather than
silently returning with a fresh, empty, healthy-looking session mid-job, which would be
indistinguishable from a correctly torn-down daemon and would corrupt evidence integrity.

### 10. `POST /system/scanner/reset` — verification-gated, never a blanket clear

Reset is an **in-daemon re-initialisation**, not a process restart. Ordered procedure, all inside the
global daemon lease:

```
R1 acquire global daemon lease (fails fast if a live lease is held)
R2 health:    GET /JSON/core/view/version              → unreachable ⇒ STOP
R3 identity:  read the instance marker context; compare recorded version + marker
R4 newSession (clean)
R5 assert stores empty: alerts == 0, sites == [], messages == 0
R6 probe:     create a throwaway context, read it back, remove it   (API actually works)
R7 re-read version; write a NEW instance marker; record it
R8 only if R2–R7 ALL succeeded: is_dirty = false, last_reset_at/by set
R9 audit the whole sequence, step by step, pass or fail; release the lease
```

**The dirty flag is never cleared without successful verification.** Any failing step leaves
`is_dirty = true`, updates `dirty_reason`, and records the failing step. There is no force parameter,
no configuration override and no automatic expiry of the dirty flag. Reset also changes no flag,
grant, approval or profile — it cannot be used as a scanning bypass.

When R2 fails (daemon unreachable) or R3 shows an identity mismatch the platform cannot fix it from
inside, so it sets `requires_operator_restart = true` and returns `503` naming the operator action.

### 11. Operator-performed container restart (the documented escalation)

Required whenever the daemon is unreachable, its identity has changed, or reset fails at R2/R3. Run
**from the operator's own shell, outside the application**:

```bash
make lab-zap-restart   # docker compose -f docker-compose.lab.yml restart zap
make lab-check         # re-verify isolation before anything else
```

Then call `POST /system/scanner/reset` to verify and clear the dirty flag. Until both succeed, gate 13
denies every job requiring the exclusive daemon, on every asset and profile. `lab/README.md` carries
this runbook, including the note that `restart: "no"` means the container will not come back on its
own, by design.

### 12. Daemon crash: what the reconciler does

| Question | Behaviour |
|---|---|
| Mark the active job failed? | Yes — `failed`, `stop_reason='daemon_unavailable'`. **Never `completed`** |
| Mark the daemon dirty? | Yes, immediately; gate 13 then blocks every asset and profile |
| Verify the old process is gone? | **Not at OS level, and this is not claimed.** Process liveness needs the Docker socket, which is forbidden. What is verified is **daemon identity and state**: an instance-marker context plus recorded version and session name, written on acquisition. A lease that existed while the marker is now absent, or a changed version/session, means the daemon restarted ⇒ dirty. `restart: "no"` prevents a silent auto-restart from masking this. Recorded as assumption **B9** |
| Require a reset before another job? | Yes — verification-gated reset (§10) only; plus an operator restart where §11 applies |
| Preserve partial observations? | Yes. Already-written `raw_observations` are immutable and retained; the job records `coverage_complete = false` |
| Can incomplete data confirm a finding? | **No.** See §13 |

### 13. Incomplete coverage cannot produce a confirmed finding

Negative evidence is unsound under truncated collection: "header absent across ≥N responses on ≥M
URLs" means nothing if collection stopped early. Therefore when `coverage_complete = false`
(daemon crash, cancellation, budget exhaustion, teardown failure):

- **negative-evidence rules are suppressed**, resolving to `inconclusive` with
  `rule_inputs.reason = 'incomplete_coverage'` instead of `confirmed`;
- **positive-evidence rules may still confirm** (a payload reflected unencoded is present
  regardless of how much else was collected);
- `coverage_complete` is a recorded rule input, so the decision is reproducible;
- the report marks the scan partial and names the stop reason.

### 14. Bounded cancellation latency (corrects "next phase boundary")

"Next phase boundary" was the wrong unit: ZAP's spider and active phases are long poll loops, so a
boundary could be minutes away. **The checkpoint is every poll tick**, plus between collection pages
and between phases. Revocation (grant or approval) sets `cancel_requested_at` in its own transaction,
so detection latency is one checkpoint.

| Step | Bound | Setting |
|---|---|---|
| 1. finish the current bounded operation | ≤ 2 s (ZAP poll tick) / ≤ 15 s (in-flight crawler request) | `CANCEL_CHECK_INTERVAL_SECONDS`, `HTTP_REQUEST_TIMEOUT_SECONDS` |
| 2. observe cancel/revocation state | same tick | — |
| 3. `stopScan` | ≤ 10 s | `ZAP_API_CALL_TIMEOUT_SECONDS` |
| 4. confirm daemon idle | ≤ 60 s | `ZAP_TEARDOWN_IDLE_TIMEOUT_SECONDS` |
| 5. teardown (`removeContext` → `newSession` → assert empty) | ≤ 25 s | per-call timeouts |
| 6. mark cancelled | ≤ 1 s | — |
| **total** | **≤ 113 s worst case; hard ceiling 120 s** | `CANCELLATION_SLA_SECONDS` |

Exceeding the ceiling is not an indefinite wait: `failed`, `stop_reason='cancel_unconfirmed'`, daemon
dirty, alert raised. Tested deterministically against the mock adapter and wall-clock against real ZAP
(invariant **I13**).
