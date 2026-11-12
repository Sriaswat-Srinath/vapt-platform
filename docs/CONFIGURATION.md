# Configuration Reference (final, pre-M1)

> **Baseline notice (R2, 2026-11-12).** This file is the approved configuration baseline. Safety
> defaults in it are not to be changed silently; a change requires an approved ADR. Section R2 at the
> end carries the settings added by the round-2 clarifications.

All settings come from the environment via `pydantic-settings`, validated at startup with fail-fast
errors. `.env.example` is committed with placeholder values; `.env*` (except `.env.example`) is
git-ignored. **No secret, provider name, model id or credential is hardcoded anywhere in the
codebase** — the LLM provider is read in exactly one module (`agent/llm/provider.py`).

Safety-relevant flags default to the **safe** value. A flag whose default is `false` can only become
true through deliberate operator action, and several are additionally gated by runtime checks that
refuse to honour the flag when its preconditions are unmet.

## Core

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `dev` | `dev` / `ci` / `prod`; `prod` tightens token lifetimes and disables dev seeding |
| `SECRET_KEY` | — (required) | token signing/hashing pepper; fail-fast if absent |
| `DATABASE_URL` | `postgresql+psycopg://vapt@postgres:5432/vapt` | password from `POSTGRES_PASSWORD` |
| `REDIS_URL` | `redis://redis:6379/0` | Celery broker + result backend |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `json` | structlog |
| `API_BASE_PATH` | `/api/v1` | |

## Scanner execution gates (all default to the safe value)

| Variable | Default | Effect when false/unset |
|---|---|---|
| `SCANNER_EXECUTION_ENABLED` | `false` | preflight gate 1 denies every scan; API returns 412 |
| `DEFAULT_SCANNER_ADAPTER` | `mock` | the mock adapter replays fixtures; ZAP is never contacted |
| `ZAP_ADAPTER_ENABLED` | `false` | the `zap` adapter is not registered at all |
| `ACTIVE_SCAN_ENABLED` | `false` | active/intrusive profiles rejected regardless of approvals |
| `DUAL_CONTROL_AVAILABLE` | `false` | gate 7 denies intrusive profiles; see ADR-0009 — **cannot be honoured unless ≥2 attested, distinct, active identities exist**, verified at startup |
| `ISOLATION_CHECK_TTL_MINUTES` | `60` | a check older than this counts as stale ⇒ gate 2 denies |
| `MAX_CONCURRENT_JOBS_GLOBAL` | `2` | |
| `MAX_CONCURRENT_JOBS_PER_ASSET` | `1` | enforced additionally by a Postgres advisory lock |

## Lab topology

| Variable | Default | Notes |
|---|---|---|
| `LAB_SUBNET` | `172.30.10.0/24` | verified free on this host: existing Docker networks occupy `172.17.0.0/16`, `172.18.0.0/16`, `172.19.0.0/16`; host LAN is `192.168.1.0/24`. `make lab-check` re-verifies before `up` |
| `LAB_NETWORK_NAME` | `vapt_lab` | `internal: true` |
| `CORE_NETWORK_NAME` | `vapt_core` | `internal: true` |
| `EDGE_NETWORK_NAME` | `vapt_edge` | only network with egress; `api` + `frontend` only |
| `MOCK_TARGET_HOSTNAME` | `shop.brakes-vapt.test` | Docker network alias, resolvable **only** inside `vapt_lab`; no workstation hosts-file entry |
| `MOCK_TARGET_PORT` | `3000` | container port |
| `MOCK_TARGET_PUBLISH` | `127.0.0.1:3000` | **loopback-bound only**; never `0.0.0.0` |
| `ZAP_API_KEY` | — (required when `ZAP_ADAPTER_ENABLED`) | from env, never committed |
| `ZAP_BASE_URL` | `http://zap:8080` | `vapt_lab` only |
| `ISOLATION_PROBE_TARGETS` | `1.1.1.1:443,8.8.8.8:53` | probes that **must fail**; plus a public DNS name that must not resolve |

Membership of `LAB_SUBNET` is **not** authorisation. `scope_grants.allowed_cidrs` narrows to the
subnet, and gates 9–10 additionally require the exact registered host and port.

## Budgets (profile rows seeded by migration; these are ceilings the profiles may not exceed)

| Variable | Default |
|---|---|
| `MAX_RPS_CEILING` | `5` |
| `MAX_CONCURRENT_REQUESTS_CEILING` | `4` |
| `MAX_TOTAL_REQUESTS_CEILING` | `5000` |
| `MAX_JOB_DURATION_SECONDS_CEILING` | `1800` |
| `HTTP_REQUEST_TIMEOUT_SECONDS` | `15` |
| `SPIDER_MAX_DEPTH_CEILING` / `SPIDER_MAX_CHILDREN_CEILING` | `5` / `20` |

## LLM (api container only; the worker receives none of these)

| Variable | Default | Notes |
|---|---|---|
| `LLM_ENABLED` | `false` | false ⇒ agent endpoints return 412; the rest of the platform works |
| `LLM_PROVIDER` | — | e.g. `anthropic`; selects an implementation from the provider registry |
| `LLM_MODEL` | — | provider-specific model id; configuration only, never a literal in code |
| `LLM_API_KEY_ENV` | `LLM_API_KEY` | *name* of the env var holding the key, so the key never appears in config dumps |
| `LLM_BASE_URL` | provider default | for a self-hosted/compatible endpoint |
| `LLM_MAX_TOKENS_PER_RUN` | `60000` | |
| `LLM_TEMPERATURE` | `0` | classification/structured output |
| `AGENT_MAX_STEPS` / `AGENT_MAX_TOOL_CALLS` / `AGENT_MAX_WALL_SECONDS` | `6` / `12` / `120` | |
| `REDACTION_VERSION` | `1.0.0` | stored per tool call; see ADR-0010 |
| `REDACTION_STRICT` | `true` | redactor error ⇒ empty result + tool error, never raw text |

## Evidence and retention (ADR-0011)

| Variable | Default |
|---|---|
| `EVIDENCE_BLOB_ROOT` | `/var/lib/vapt/evidence` (named volume, never a repo bind mount) |
| `EVIDENCE_MAX_BODY_BYTES` | `2097152` |
| `RETENTION_RAW_BLOB_DAYS` | `90` |
| `RETENTION_REDACTED_EVIDENCE_DAYS` | `365` |
| `RETENTION_RAW_OBSERVATION_DAYS` | `365` |
| `RETENTION_AUDIT_DAYS` | not configurable — audit is never pruned in the MVP |
| `RAW_EVIDENCE_ACCESS_ROLE` | `admin` (not lowerable by config) |

## Threat intelligence (offline only — the worker has no egress)

| Variable | Default |
|---|---|
| `EPSS_SNAPSHOT_PATH` / `KEV_SNAPSHOT_PATH` | unset ⇒ `epss_score` / `kev_listed` are NULL, never estimated |
| `INTEL_SNAPSHOT_MAX_AGE_DAYS` | `30` (older ⇒ used but flagged stale in the report) |

## Startup validation (fail-fast)

1. `SECRET_KEY`, `DATABASE_URL`, `REDIS_URL` present and reachable.
2. Any profile exceeding a ceiling ⇒ refuse to start.
3. `DUAL_CONTROL_AVAILABLE=true` with fewer than two attested, distinct, active identities ⇒ the flag
   is forced false, a warning is logged and audited, and intrusive profiles stay disabled.
4. `ACTIVE_SCAN_ENABLED=true` while `DUAL_CONTROL_AVAILABLE` is false ⇒ active profiles remain
   rejected at gate 7 (both conditions are required, not either).
5. `ZAP_ADAPTER_ENABLED=true` without `ZAP_API_KEY` ⇒ refuse to start.
6. `LLM_ENABLED=true` without `LLM_PROVIDER`, `LLM_MODEL` and a resolvable key env var ⇒ refuse to
   start (rather than silently disabling the agent).
7. `MOCK_TARGET_PUBLISH` not loopback-bound ⇒ refuse to start.

---

## R2 additions (2026-11-12)

### Scanner daemon serialisation (ADR-0008 R2)

| Variable | Default | Notes |
|---|---|---|
| `ZAP_MAX_CONCURRENT_JOBS` | `1` | **clamped in code**: any value > 1 is rejected at startup, not silently honoured. Raising it requires a superseding ADR |
| `ZAP_DAEMON_LOCK_KEY` | `vapt:zap:daemon` | global advisory-lock key; held across the complete session lifecycle |
| `ZAP_LEASE_HEARTBEAT_SECONDS` | `10` | lease liveness |
| `ZAP_LEASE_STALE_SECONDS` | `60` | a lease older than this with no held advisory lock ⇒ teardown unproven ⇒ **daemon dirty** |
| `ZAP_TEARDOWN_IDLE_POLL_SECONDS` / `ZAP_TEARDOWN_IDLE_TIMEOUT_SECONDS` | `2` / `60` | confirm-idle bounds; timeout ⇒ dirty |
| `SCANNER_DIRTY_BLOCKS_ALL_ADAPTERS` | `false` | dirty state always blocks the affected adapter on every asset; `true` additionally blocks other adapters |

There is **no** setting that clears a dirty daemon. Recovery is `POST /system/scanner/reset` (admin,
audited) only.

### Dual control (ADR-0009 R2)

| Variable | Default | Notes |
|---|---|---|
| `DUAL_CONTROL_AVAILABLE` | `false` | an **input**, never the effective value. Effective = flag AND ≥2 attested, distinct, active identities, recomputed at startup **and at every gate 7 evaluation** |
| `DUAL_CONTROL_MIN_IDENTITIES` | `2` | floor-clamped at 2; a lower value is rejected at startup |
| `APPROVAL_INVALIDATION_ON_IDENTITY_CHANGE` | `true` | **not disableable**; present for documentation and assertion only — a `false` value is rejected at startup |

No environment variable, column, API field or profile setting can set the effective dual-control
value directly or skip its recomputation.

### Authorisation document (owner instruction R2-14)

| Variable | Default | Notes |
|---|---|---|
| `AUTHORISATION_DOC_ROOT` | `lab/authorisation` | documents are read, hashed and verified from here |
| `REQUIRE_SIGNED_AUTHORISATION` | `true` | **not disableable**; a `false` value is rejected at startup |

A grant cannot reach `active` unless `document_state='signed_verified'` (DB CHECK), and gate 5
re-verifies the SHA-256 and the signed state on every evaluation. No code path sets `signed_verified`
automatically; it requires a human action recorded with actor and timestamp. **Until the operator
signs `lab/authorisation/MOCK-WEB-001.md` and records verification, scanner execution is denied.**

### Redaction (ADR-0010 R2)

| Variable | Default | Notes |
|---|---|---|
| `REDACTION_HMAC_KEY_ENV` | `REDACTION_HMAC_KEY` | *name* of the env var holding the key, so the key never appears in a config dump |
| `REDACTION_KEY_ID` | `v1` | recorded per tool call; rotation mints a new id and ends correlation with older refs |
| `REDACTION_REF_LENGTH` | `12` | base32 chars of the HMAC retained |
| `REDACTION_MAX_DECODE_PASSES` | `2` | decode-then-scan depth for encoded credentials |
| `REDACTION_MAX_PARSE_DEPTH` / `REDACTION_MAX_PARSE_NODES` / `REDACTION_MAX_PARSE_BYTES` | `20` / `50000` / `2097152` | parser resource limits; exceeding them ⇒ whole-value redaction, never passthrough |
| `REDACTION_STRICT` | `true` | retained from the baseline; **not disableable** — a `false` value is rejected at startup |
| `LLM_EXPOSE_CONTENT_HASHES` | `false` | **not disableable**; plain SHA-256 values are never placed in an LLM-bound payload |

`REDACTION_HMAC_KEY` is required whenever `LLM_ENABLED=true`; startup fails if it is absent, shorter
than 32 bytes, or equal to a known example value. It is never logged, never audited, never persisted
to the database and never sent to the provider.

### Evidence retention (ADR-0011 R2)

| Variable | Default | Notes |
|---|---|---|
| `RETENTION_ENABLED` | `false` | retention stays off until the five mechanisms in `EVIDENCE_LIFECYCLE.md` are implemented and tested |
| `RETENTION_SCHEDULE_CRON` | `0 3 * * *` | |
| `RETENTION_DRY_RUN` | `true` | first-run default: plan and report, delete nothing |
| `RETENTION_MAX_ITEMS_PER_RUN` | `5000` | bounds blast radius |
| `RETENTION_ITEM_MAX_ATTEMPTS` | `2` | then `failed` + reported, **and `retention_state.halted` is set**, blocking new destructive runs until an audited admin acknowledgement (ADR-0011 R3 §12.5) |
| `RETENTION_AUTO_RESUME_INTERRUPTED` | `true` | a half-finished purge is not a state to sit in; resumption is audited |
| `RETENTION_PIN_BLOBS_FOR_REPORTS` | `false` | reports pin redacted evidence only, so report generation does not extend secret lifetime |
| `EVIDENCE_ENCRYPTION_MODE` | `none` | the only accepted MVP value; reported verbatim by `/system/capabilities` as `none (host FDE assumed, unverified)` |
| `RAW_RESTORATION_ENABLED` | `false` | the request flow exists; the MVP has no restoration capability (purge is final) |
| `ORPHAN_SWEEP_ENABLED` | `true` | reports only; never deletes autonomously |

`RETENTION_AUDIT_DAYS` remains absent by design — audit is never pruned.

### Startup validations added this round

8. `ZAP_MAX_CONCURRENT_JOBS > 1` ⇒ refuse to start.
9. `DUAL_CONTROL_MIN_IDENTITIES < 2`, `APPROVAL_INVALIDATION_ON_IDENTITY_CHANGE=false`,
   `REQUIRE_SIGNED_AUTHORISATION=false`, `REDACTION_STRICT=false`,
   `LLM_EXPOSE_CONTENT_HASHES=true` or `EVIDENCE_ENCRYPTION_MODE != none` ⇒ refuse to start.
   These are the safety defaults that configuration may not weaken.
10. `LLM_ENABLED=true` without a valid `REDACTION_HMAC_KEY` (≥32 bytes, not an example value) ⇒
    refuse to start.
11. `RETENTION_ENABLED=true` while any of the five lifecycle mechanisms is absent (feature probe) ⇒
    refuse to start.
12. Any `scope_grants` row in `active` whose `document_state != 'signed_verified'` ⇒ refuse to start
    (indicates out-of-band tampering with the grant table).

---

## R3 additions (2026-11-12)

No existing default is changed by this round; every entry below is new.

### Cancellation and scanner API bounds (ADR-0008 R3 §14)

| Variable | Default | Notes |
|---|---|---|
| `CANCEL_CHECK_INTERVAL_SECONDS` | `2` | cancellation checkpoint cadence: every poll tick, between collection pages, between phases |
| `ZAP_API_CALL_TIMEOUT_SECONDS` | `10` | per-call bound for `stopScan`, `removeContext`, `newSession` |
| `CANCELLATION_SLA_SECONDS` | `120` | hard ceiling on revocation/cancel → terminal state; exceeding it ⇒ `cancel_unconfirmed` + dirty daemon + alert (invariant I13) |

### Scanner reset and operator escalation (ADR-0008 R3 §9–11)

| Variable | Default | Notes |
|---|---|---|
| `SCANNER_RESET_REQUIRES_VERIFICATION` | `true` | **not disableable** — a `false` value is rejected at startup. The dirty flag never clears without steps R2–R7 all succeeding |
| `SCANNER_RESET_PROBE_TIMEOUT_SECONDS` | `30` | bound for the health/identity/probe steps |
| `SCANNER_ALLOW_CONTAINER_CONTROL` | `false` | **not settable to `true`** — rejected at startup. Documents that the platform has no container-control capability (no Docker socket) and must not acquire one |

There is no setting that force-clears a dirty daemon, and none that grants container control.

### Coverage and validation soundness (ADR-0008 R3 §13)

| Variable | Default | Notes |
|---|---|---|
| `SUPPRESS_NEGATIVE_EVIDENCE_ON_PARTIAL_COVERAGE` | `true` | **not disableable** — rejected at startup if `false`. Negative-evidence rules cannot confirm when `coverage_complete=false` |

### Evidence provenance (ADR-0011 R3 §13)

| Variable | Default | Notes |
|---|---|---|
| `INGESTION_ENFORCE_PINNED_PEER` | `true` | **not disableable**; observations whose peer IP ∉ `pinned_ips` or whose host/port differ from the registered asset are rejected and audited |
| `PROVENANCE_VERIFY_SCHEDULE_CRON` | `30 3 * * *` | chain-integrity sweep |
| `PROVENANCE_QUARANTINE_ON_VIOLATION` | `true` | **not disableable**; violating findings are flagged and excluded from reports |

### Retention halt (ADR-0011 R3 §12.5)

| Variable | Default | Notes |
|---|---|---|
| `RETENTION_HALT_ON_INCONSISTENCY` | `true` | **not disableable**; a failed item or unexpectedly missing blob blocks new destructive runs |
| `RETENTION_FSYNC_AFTER_UNLINK` | `true` | **not disableable**; without it a crash could resurrect a file the database calls purged |
| `RETENTION_VERIFY_BLOB_IDENTITY` | `true` | **not disableable**; pre-unlink `lstat`/real-path/size checks — the platform refuses to delete a file it cannot positively identify |

### Redaction key management (ADR-0010 R3)

| Variable | Default | Notes |
|---|---|---|
| `REDACTION_KCV_LABEL` | `vapt-kcv` | key check value input; a changed KCV under an unchanged `REDACTION_KEY_ID` is a startup misconfiguration |
| `REDACTION_DISABLE_AGENT_ON_KCV_MISMATCH` | `true` | **not disableable**; the agent is disabled until the key id is corrected |

### Startup validations added this round

13. `SCANNER_RESET_REQUIRES_VERIFICATION=false`, `SCANNER_ALLOW_CONTAINER_CONTROL=true`,
    `SUPPRESS_NEGATIVE_EVIDENCE_ON_PARTIAL_COVERAGE=false`, `INGESTION_ENFORCE_PINNED_PEER=false`,
    `PROVENANCE_QUARANTINE_ON_VIOLATION=false`, `RETENTION_HALT_ON_INCONSISTENCY=false`,
    `RETENTION_FSYNC_AFTER_UNLINK=false`, `RETENTION_VERIFY_BLOB_IDENTITY=false` or
    `REDACTION_DISABLE_AGENT_ON_KCV_MISMATCH=false` ⇒ **refuse to start**.
14. `CANCELLATION_SLA_SECONDS` below the sum of the step bounds ⇒ refuse to start (an unreachable SLA
    is a misconfiguration, not a tighter guarantee).
15. KCV mismatch under an unchanged `REDACTION_KEY_ID` ⇒ agent disabled, audited.
16. `retention_state.halted = true` at startup ⇒ destructive retention runs refused until acknowledged.
