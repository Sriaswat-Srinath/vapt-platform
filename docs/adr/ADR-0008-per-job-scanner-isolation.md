# ADR-0008: Per-job scanner isolation via a long-lived ZAP daemon with per-job contexts

- Status: Accepted (2026-11-12) — revisit at M11
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
