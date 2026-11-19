# M9 — scanner configuration and containment, for independent review

This is the material for step 3 of the M9 sequence: **independently review the scanner
configuration and network containment** before anything is enabled. It states what will run, what
cannot run, and what each claim rests on. Nothing in this document enables anything.

Reviewer: please disagree with any line you cannot verify yourself.

---

## 1. What would actually run

Profile **`zap-passive`** — the only profile that should be used for M9.

| Setting | Value | Why it is this value |
|---|---|---|
| `adapter_name` | `zap` | requires `ZAP_ADAPTER_ENABLED=true`, a separate decision |
| `is_intrusive` | **false** | no payloads are sent; nothing is modified |
| `active_scan` | **false** | ZAP's active scanner is not started. Enforced again by `ACTIVE_SCAN_ENABLED=false` at gate 7 |
| `max_requests_per_second` | 5 | a browsing-speed rate against a container on the same host |
| `max_concurrent_requests` | 4 | |
| `max_total_requests` | 5000 | a hard ceiling; the job stops with `budget_exhausted` |
| `max_duration_seconds` | 1800 | 30 minutes, then the job stops |
| `spider_max_depth` / `max_children` | 5 / 20 | bounds the crawl |
| `method_denylist` | `DELETE`, `PUT`, `PATCH` | no state-changing verbs |
| `excluded_path_patterns` | `/rest/user/logout`, `/api/Users`, `/rest/user/reset-password`, `/ftp` | logout destroys the session under test; the others mutate user state or loop |

**Not used for M9:** `zap-active-intrusive` (`is_intrusive=true`, `active_scan=true`). It is
unreachable anyway — gate 7 requires two independent approvals and dual control is unavailable
with one operator.

## 2. What the scanner can reach

| Property | State | Evidence |
|---|---|---|
| Worker networks | `vapt_core` + `vapt_lab` only | `NET-A:worker` probe |
| Worker default route | **none** | `NET-F:worker` = NONE |
| Worker → internet | **ENETUNREACH** | `NET-G1` |
| Worker → LAN gateway | **ENETUNREACH** | `NET-G2` |
| Worker → egress proxy | **ENETUNREACH** | `NET-G3` |
| Worker → the registered target | REACHABLE | `NET-G8` |
| Worker → ZAP control port | REACHABLE | `NET-G9` |
| Lab → internet | **ENETUNREACH** | `I2*` lab probes |
| Lab → host wildcard listener `:5433` | TIMEOUT (dropped) | `PUB-2R:5433` — recorded, **does not** excuse the hygiene failure |

115/115 network probes pass, and `scripts/prove_net_failure.sh` demonstrates that the check can
fail when a route is deliberately introduced. Containment is measured, not assumed.

## 3. What stops it today

Run `scripts/m9_readiness.py` for the live picture. At the time of writing, four gates deny:

1. `scanner_execution_enabled` — the kill switch is off.
2. `lab_isolation_valid` — **host hygiene fails**: a foreign `0.0.0.0:5433` listener
   (`corelayer-lab-db`, another project on this machine) is enumerated by `PUB-2`. The lab cannot
   presently reach it, and that measurement does not change the verdict (ADR-0015).
3. `grant_active` — the authorisation document is an unsigned draft.
4. `target_resolution` — the API cannot resolve the lab hostname, which is by design; the worker
   is the authoritative evaluator and resolves it at execution time.

## 4. The authorisation chain, and what now enforces it

The document promises that editing it after approval invalidates the grant. Until this milestone
that was **recorded but never checked**. Gate 5 now:

* requires the grant to record a document digest;
* requires a **fresh attestation** of the document's current digest (`make attest-authorisation`);
* **denies** if the attested digest differs from the one the grant was approved against;
* denies if the attestation is older than `AUTHORISATION_ATTESTATION_TTL_MINUTES` (default 24h).

`scripts/prove_authorisation_tamper.sh` demonstrates it on a scratch copy: PASS with the approved
digest → **DENY** after an edit → PASS again when reverted. Policy version **1.2.0**.

## 5. What a reviewer should check independently

1. `docker inspect vapt_worker` — networks, and no `vapt_egress`/`vapt_wan`.
2. `make net-verify` — 115 probes, and read the `NET-G*` rows yourself.
3. `make lab-check` — containment and host hygiene as separate verdicts.
4. The `zap-passive` row in the database matches §1 (`GET /api/v1/scan-profiles`).
5. `sha256sum lab/authorisation/MOCK-WEB-001.md` matches the digest the grant records **after**
   signing.
6. `ACTIVE_SCAN_ENABLED=false` in the running container's environment, not just in `.env`.

## 6. The enabling sequence, in order, with who acts

| # | Action | Who |
|---|---|---|
| 1 | Sign §7 of `lab/authorisation/MOCK-WEB-001.md` by hand | **a human** — nothing in this repository may do it |
| 2 | `make attest-authorisation` (records the signed document's digest) | operator |
| 3 | `POST /scope-grants/{id}/verify-document` with `signed=true` and that digest | admin |
| 4 | `POST /scope-grants/{id}/activate` | **a second person** — the API refuses the requester |
| 5 | Resolve the `:5433` listener, then `make lab-check && make isolation-report` | owner of that service |
| 6 | Set `ZAP_ADAPTER_ENABLED=true` | owner, as a separate decision |
| 7 | Set `SCANNER_EXECUTION_ENABLED=true`, leaving `ACTIVE_SCAN_ENABLED=false` | owner, as a separate decision |
| 8 | `scripts/m9_readiness.py` — expect 13/13 | operator |
| 9 | Start a `zap-passive` assessment in **live** mode | analyst |

Steps 1 and 4 are deliberately not automatable: one is a signature, the other requires a different
person. If either is simulated, the resulting findings are not authorised findings.
