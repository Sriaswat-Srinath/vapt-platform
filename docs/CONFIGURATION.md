# Configuration Reference (final, pre-M1)

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
