# Scope and Safety Architecture

The safety layer is **deterministic Python with no LLM involvement, no network calls at decision
time, and no silent defaults**. Every decision is a value object that is persisted.

## 1. Defence in depth — four independent layers

| Layer | Mechanism | Fails closed because |
|---|---|---|
| L1 Network | `lab` and `core` Docker networks are `internal: true`; ZAP and Juice Shop sit only on `lab`; the worker is dual-homed `core`+`lab` and holds no LLM credentials | no default route off-host exists, so an app bug cannot reach the internet |
| L2 Process | scanner runs as non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, pids/memory/cpu limits, no Docker socket, dedicated tmpfs workdir | subprocess arg arrays only, never `shell=True` |
| L3 Policy | `safety/preflight.py` ordered gate chain evaluated before every discovery run and every scan job, and re-evaluated on resume | unknown input → `deny`; any gate exception → `deny` |
| L4 Runtime | per-request redirect guard, host/IP re-check per request, token-bucket rate limiter, concurrency semaphore, request cap, wall-clock timeout, cooperative cancellation | budget exhaustion aborts the job with `stop_reason` |

## 2. Preflight gate chain (ordered, short-circuit on first denial)

1. `scanner_execution_enabled` — global flag.
2. `lab_isolation_valid` — latest `lab_isolation_checks` row passed and not expired.
3. `asset_registered` — asset exists, state `active`.
4. `environment_is_mock` — `assets.environment == 'mock_lab'`.
5. `grant_active` — a `scope_grants` row is `active`, `valid_from <= now < valid_until`, not revoked,
   and its stored `document_sha256` matches the authorisation document on disk.
6. `profile_allowed` — requested `profile_key ∈ grant.allowed_profiles`.
7. `intrusive_approval` — if `profile.is_intrusive` or `profile.active_scan`: `grant.intrusive_allowed`
   **and** an `approvals` row of kind `intrusive_profile`, state `approved`, unexpired, decided by a
   different person than the requester.
8. `target_resolution` — resolve hostname (A/AAAA) via the lab resolver; **every** returned address
   must be inside `grant.allowed_cidrs`; zero addresses, mixed in/out results, or a CNAME leaving the
   allowed host set ⇒ deny. Resolved IPs are pinned into the job and reused for the duration
   (resolve-once, connect-to-pinned-IP with `Host` header) to close the DNS-rebinding window.
9. `port_allowed` — `asset.port ∈ grant.allowed_ports` and in the profile's port allowlist.
10. `scope_rules` — target URL matches ≥1 `include` rule and 0 `exclude` rules; method ∈ the rule's
    `method_allowlist` and ∉ `profile.method_denylist`.
11. `concurrency_budget` — asset-level and global in-flight job caps not exceeded.
12. `no_conflicting_job` — no other running job on the same asset (serialised per asset).

Output: `ScopeDecision{policy_version, decision, gate_results[], resolved_ips[]}` → persisted and
audit-logged whether it allows or denies. `scope_policy.evaluate()` is a **pure function** of an
immutable `ScopeRequest` snapshot, which makes the whole chain table-testable.

## 3. Runtime enforcement

- **Redirect guard**: HTTP redirects are never auto-followed by the client. Each `Location` is
  re-evaluated through gates 8–10 against the pinned IP set; out-of-scope redirects are dropped,
  counted, and recorded as `audit_log(action='redirect_blocked')` plus an inventory note. ZAP is
  additionally configured with its own context include/exclude regexes as a second barrier.
- **Rate limiting**: token bucket at `profile.max_requests_per_second`, enforced in the HTTP client
  wrapper used by discovery and (via ZAP's own throttle settings) by the scanner.
- **Concurrency**: `asyncio.Semaphore(profile.max_concurrent_requests)` per job; per-asset job
  serialisation via a Postgres advisory lock so two workers cannot double-scan.
- **Caps and timeouts**: `max_total_requests`, `max_duration_seconds`, plus a per-request timeout.
  Exceeding any cap transitions the job to `completed` with `stop_reason='budget_exhausted'` (not
  `failed` — the partial result is valid and reportable).
- **Pause/cancel**: `pause_requested_at` / `cancel_requested_at` are polled at every phase boundary
  and between request batches; cancel also calls the adapter's `cancel()` (ZAP `stopScan` +
  `removeContext`) and then verifies the scanner reports idle. A job that cannot be confirmed stopped
  goes to `failed` with `stop_reason='cancel_unconfirmed'` and raises an alert — it never silently
  keeps running.
- **Excluded operations**: `profile.excluded_path_patterns` (logout, password reset, delete-ish
  endpoints) and `method_denylist` default `{DELETE, PUT, PATCH}`. Attack classes DoS, brute force,
  persistence, exfiltration and exploitation-beyond-detection are excluded by ZAP policy
  configuration (`lab/zap/zap-baseline-policy.xml`) **and** by an adapter-level rule-id denylist, so
  disabling one does not enable the behaviour.

## 4. Isolation verification (`safety/isolation.py`)

`scripts/lab_isolation_check.sh` + an API-triggered probe:

- enumerate the `lab` network, assert `internal: true` and no gateway route;
- from inside the ZAP container, attempt TCP to 2–3 fixed public IPs and a DNS query for a public
  name, expecting failure on all;
- assert `shop.brakes-vapt.test` resolves **only** inside `lab` and to a lab-subnet address;
- assert the ZAP container has no `/var/run/docker.sock` bind.

Result → `lab_isolation_checks`. `passed=false` or `valid_until < now` ⇒ gate 2 denies every scan.
The check runs on worker startup, on a scheduled interval, and before any job whose last check is
older than the configured TTL.

## 5. What the LLM may never do

Enforced structurally, not by prompt:

- No shell, no filesystem, no HTTP client, no DB session in `agent/` (import-linter + runtime deny).
- Cannot create, start, resume or cancel scans; cannot register assets; cannot create or activate a
  scope grant or approval; cannot edit profiles, budgets, rate limits or exclusions.
- Cannot write `validation_state`, `severity`, `confidence`, `cvss_*`, `epss`, `kev_listed`,
  `priority_score`. `validation_events` has a CHECK rejecting `actor_kind='agent'`; the agent's only
  write is an `agent_suggestions` row requiring human acceptance.
- Tool arguments are pydantic-validated and resolved against existing row ids scoped to the session's
  asset; free-text URLs/hosts/commands are not accepted by any tool signature.
- The output guard strips privileged fields from model output, requires every factual claim to carry a
  citation to a retrieved `finding_id`/`evidence_id`, and halts the run (`halted_by_guard`) on
  violation.
- Scanner output, page content and evidence injected into the agent context are wrapped as untrusted
  data with an explicit instruction boundary; the graph has no node that can act on instructions
  found there.

## 6. Test obligations (must be green for any merge)

`backend/tests/safety/` — table-driven cases covering: unregistered asset, archived asset,
non-mock environment, expired/revoked/hash-mismatched grant, profile not in allowlist, intrusive
without dual-control approval, hostname resolving outside `allowed_cidrs`, split-horizon resolution,
rebinding between preflight and request, disallowed port, excluded path, denied method, out-of-scope
redirect (absolute, protocol-relative, meta-refresh, 307/308), rate-limit and request-cap
enforcement, concurrent-job rejection, cancellation mid-phase, isolation check stale/failed, and
agent attempts at each forbidden write. Each case asserts the persisted `ScopeDecision` and the
audit row, not just the HTTP status.

---

## 7. Amendments from the approved decision log (2026-11-12)

Binding changes to the chain and runtime described above. See `DECISION_LOG.md` and ADR-0008…0011.

### 7.1 Gate 7 — intrusive approval, strengthened (D2, D7, ADR-0009)

Gate 7 now denies unless **all** hold:
`profile.is_intrusive or profile.active_scan` ⇒
`ACTIVE_SCAN_ENABLED` **and** `DUAL_CONTROL_AVAILABLE` **and** `grant.intrusive_allowed`
**and** an `approvals` row of kind `intrusive_profile`, state `approved`, unexpired,
with `decided_by != requested_by` **and** both identities present in `operator_identities` as
attested, distinct and active.

`DUAL_CONTROL_AVAILABLE` cannot be honoured unless ≥2 attested distinct active identities exist — a
startup check forces the flag false otherwise, logs and audits the downgrade. Consequently
**intrusive and active scanning are disabled in a single-operator environment**, and approvals
recorded there are labelled `simulated_dual_control: true` in the API, the UI and every report. No
configuration enables intrusive scanning while dual control is unavailable.

### 7.2 Gate 8/9/10 — subnet membership is not authorisation (confirmation 3)

`LAB_SUBNET=172.30.10.0/24` bounds `allowed_cidrs`, but residence in the subnet authorises nothing on
its own. Gate 9 still requires the exact registered port, and gate 10 the exact registered host and
path/method allowlist. A second, unregistered container inside the lab subnet is **out of scope** and
any finding about it is rejected and audited.

### 7.3 Per-job scanner isolation (D4, ADR-0008 + R2)

**One active ZAP job globally**, serialised by a **global** daemon lease
(`pg_advisory_lock('vapt:zap:daemon')` + a `scanner_daemon_leases` row with heartbeat) held across the
complete session lifecycle — the per-asset lock cannot serialise `newSession`, which is a
daemon-global operation. Per-asset locks and job caps are retained as narrower budget controls. A new
**gate 13 `scanner_daemon_available`** denies when the daemon is dirty, a live lease is held, or a
stale lease is unreconciled. Each job: `newSession` → assert empty alert/site/message stores → create context `job-<job_id>` with
include/exclude regexes → run → `finally`: `stopScan` → confirm idle → `removeContext` →
`newSession` → assert empty. Teardown failure ⇒ job `failed` with
`stop_reason='teardown_unconfirmed'` **and** a daemon-dirty flag that blocks new jobs until an admin
runs `POST /system/scanner/reset` — blocking **every** asset and profile, not just the affected one.
A stale or unheld lease found by the next acquirer also marks the daemon dirty, because the previous
teardown is unproven and daemon state is therefore untrusted. Adapter handles persist in `scan_jobs.adapter_handle` so a worker restart
re-attaches or fails explicitly rather than orphaning daemon state.

### 7.4 LLM redaction boundary (D3, ADR-0010)

§5 is extended: the agent not only cannot *act* outside its catalogue, it cannot *see* unredacted
text. Agent tools return `RedactedText`, constructible only by `agent/redaction.py`; import-linter
forbids `agent/` from importing blob or raw-evidence readers. Two independent redaction stages (on
write, and again on egress) cover credentials, cookies, bearer tokens, CSRF tokens, API keys,
JWT/PEM/high-entropy strings and personal-data patterns. Redaction is **structure-aware** (JSON incl.
nested arrays, URL query parameters, HTML forms, multipart, XML, exception messages, tool errors and
stack traces, and recognisable encoded credentials), replacing values with
`<redacted:kind=…,len=…,ref=hmac:v1:…>` — a **keyed** HMAC reference, never a plain digest of the
secret (ADR-0010 R2 §7). Plain content hashes never cross the boundary. A redactor failure yields an
empty result plus a tool error, never raw text. `redaction_version`, `redaction_key_id` and a
per-call `redaction_report` are persisted, so what crossed the boundary is reconstructible.

### 7.5 Analyst override preserves the automated result (D10)

`POST /findings/{id}/analyst-classification` requires a justification, and appends a
`validation_events` row with `actor_kind='human'`, actor identity, timestamp and the prior state. The
engine's original transition is **never** overwritten or deleted; the UI and the report show both the
automated classification and the human override with its justification.

### 7.6 Evidence access control (D11, ADR-0011)

Redacted evidence: role `analyst`+. Unredacted blob content: `GET /evidence/{id}/content?raw=true`,
role `admin` only (not lowerable by configuration), justification required, audit-logged; no bulk raw
export; no agent code path. Retention is a scheduled, audited purge that nulls content while keeping
hash-only provenance stubs; audit itself is never pruned.

### 7.7 Test obligations added to §6

Dual-control downgrade (flag forced false with <2 attested identities; intrusive denied anyway) ·
same-identity approval rejected · unattested identity rejected · cross-job contamination
(consecutive jobs on different seed sets; job B must see none of job A's alerts/sites/messages) ·
teardown failure sets the daemon-dirty flag and blocks new jobs · redaction of each secret class,
redactor-failure fail-closed, and an `agent/` import attempt on a raw reader failing CI ·
unregistered in-subnet host rejected · non-loopback publish refused at startup · raw evidence access
denied to `analyst` and audited for `admin` · retention purge keeps provenance and respects the
report-artifact pin.

---

## 8. Amendments R3 (2026-11-12)

### 8.1 Synthetic-only enforcement is provenance-based (ADR-0011 R3 §13)

The `environment='mock_lab'` CHECK is metadata; the enforcement is the route plus ingestion controls:
no evidence exists outside a job (worker-only writes, `raw_observations.job_id NOT NULL`); ingestion
independently rejects observations whose peer IP ∉ `scan_jobs.pinned_ips` or whose host/port differ
from the registered asset (rejected, audited, never stored); `assets.environment`, `hostname`,
`protocol` and `port` are immutable by trigger; and `GET /system/provenance/verify` walks every
evidence row against the chain `evidence → raw_observation → scan_job → scope_decision(allow) →
asset(mock_lab) → scope_grant(signed_verified)` plus `asset_resolutions` and the covering
`lab_isolation_checks` record, quarantining violations.

### 8.2 Scanner reset cannot restart containers (ADR-0008 R3 §9–11)

Docker socket access is permanently prohibited, so the platform **cannot start, stop or restart the
ZAP container** and no code path attempts it. `POST /system/scanner/reset` is an in-daemon
re-initialisation whose nine steps (lease → health → identity → `newSession` → assert empty → API
probe → new marker → clear → audit) **must all succeed before the dirty flag clears**. There is no
force parameter, no config override, no automatic expiry. Where the daemon is unreachable or its
identity has changed, the endpoint sets `requires_operator_restart`, returns `503`, and the operator
runs `make lab-zap-restart` then `make lab-check` **outside the application**. ZAP runs with
`restart: "no"` so a crashed daemon stays down instead of returning with a deceptively clean session.

### 8.3 Bounded cancellation (ADR-0008 R3 §14)

Cancellation checkpoints are every ZAP poll tick (`CANCEL_CHECK_INTERVAL_SECONDS=2`), between
collection pages and between phases — **not** at the end of a long phase. Revocation sets
`cancel_requested_at` in its own transaction. Each teardown step is individually bounded and the total
is capped by `CANCELLATION_SLA_SECONDS=120`; exceeding it yields `failed` +
`stop_reason='cancel_unconfirmed'` + dirty daemon + alert, never an indefinite wait.

### 8.4 Incomplete coverage cannot confirm (ADR-0008 R3 §13)

When `coverage_complete=false`, negative-evidence validation rules are suppressed and resolve to
`inconclusive` (`reason='incomplete_coverage'`); positive-evidence rules may still confirm.
`coverage_complete` is a recorded rule input, and the report marks the scan partial.

### 8.5 Purge crosses two systems that cannot be atomic (ADR-0011 R3 §12)

Postgres transactions and filesystem operations cannot be made atomic together, so the crossing is
made recoverable instead: intent is committed first (`pending_delete`), the file is unlinked, verified
absent and its directory `fsync`ed, and only then is the row updated. The sole reachable
inconsistency is "bytes gone, row stale" — detectable and repairable. The inverse, "row says purged
while the secret is on disk", is unreachable. Any failed item or unexpectedly missing blob **halts new
destructive runs** until an audited admin acknowledgement.

### 8.6 HMAC key handling (ADR-0010 R3)

Key only from the environment, held as `SecretBytes`, never persisted; refs carry key id and
`hmac_alg`; no key history retained; rotation audited and a silent rotation detected by a key check
value (which disables the agent until the id is corrected); integrity hashes are unkeyed and unaffected
by rotation; the key value cannot appear in logs, config dumps, exceptions or prompts (four
independent mechanisms, asserted by invariant I11).

### 8.7 Test obligations added

The invariant suite `backend/tests/invariants/` (I1–I14) plus its manifest test, per
[INVARIANTS.md](INVARIANTS.md). Specifically added this round: provenance-chain violation quarantine ·
ingestion rejection on peer-IP/host/port mismatch · `assets` identity immutability · reset refusing to
clear the dirty flag at each failing step · operator-restart escalation path · cancellation SLA ·
negative-evidence suppression under incomplete coverage · the purge crash-recovery matrix at every
boundary · retention halt blocking new runs · HMAC key non-appearance and KCV detection.

---

## 9. Amendments after M1 (2026-11-12) — measured network facts

### 9.1 Reachability classes (ADR-0012)
`internal: true` is **container→internet and container→LAN isolation only**. Measured on the lab:
container→internet `ENETUNREACH`; container→LAN `ENETUNREACH`; container→host via LAN IP
`ENETUNREACH`; **container→host via the lab gateway `172.30.10.1` reachable** for any host service
bound on `0.0.0.0`; **host→container reachable**. Isolation claims in this document are to be read
with that vocabulary. Consequences enforced: every host publish binds `127.0.0.1` (probe `I14`);
host-wide `0.0.0.0` listeners are reported (`I14b`); the lab gateway is never a valid target (gates
8–10 already require the exact registered IP; the D19 forwarder refuses it too).

### 9.2 Host-side loopback forwarder (D19)
Fixed destination (registered target only; refuses hostnames, the gateway, anything outside the lab
subnet and any argument), literal loopback bind, L4 relay with no proxy semantics, explicit shutdown,
never auto-started, negative-tested (`tests/lab/test_forwarder_and_pinning.py`).

### 9.3 API egress boundary (ADR-0012, `NETWORK_ARCHITECTURE.md` §4)
Outbound from the API exists only as `CONNECT` to the one configured LLM host:443 via an allowlisting
egress proxy; everything else is denied below the application. The worker holds no proxy variables,
no provider credentials and no API token, and cannot reach the proxy or the API — so it has no
indirect internet path either. These become M2 tests before any M2 feature is accepted.

### 9.4 Restart acknowledgement (D23, ADR-0008 R4 §16)
Bound to container id, start time, a daemon instance UUID, a nonce, operator identity and timestamps;
single-use, atomically consumed, short-lived; any mismatch invalidates; never clears dirty state on
its own.
