# Dependencies

All versions are pinned (lock files committed). Scanner and target images are pinned by **digest**,
not tag, so a lab rebuild cannot silently change what is being tested.

## Backend (Python 3.12)

| Package | Purpose |
|---|---|
| fastapi, uvicorn[standard] | API |
| pydantic 2.x, pydantic-settings | schemas, config, fail-fast validation |
| sqlalchemy 2.x, alembic, psycopg[binary] | ORM, migrations, driver |
| celery[redis], redis | async jobs, cancellation/revoke |
| httpx | discovery client (rate-limited wrapper) |
| beautifulsoup4 + lxml | HTML/form/parameter extraction |
| tenacity | bounded retries with jitter |
| python-zap (`zaproxy` client) *or* raw httpx against the ZAP REST API | ZAP control |
| langgraph, langchain-core | agent graph |
| anthropic | default LLM provider |
| cvss | CVSS vector parsing/scoring (no invention, parse-and-validate only) |
| structlog, orjson | structured JSON logging |
| jinja2, weasyprint | report HTML → PDF |
| passlib[argon2] | API token hashing |
| python-ulid / uuid7 | sortable ids |

Dev/test: pytest, pytest-asyncio, pytest-cov, testcontainers[postgres], respx (HTTP mocking),
hypothesis (fingerprint/scope property tests), freezegun, ruff, mypy (strict), import-linter,
bandit, pip-audit, pre-commit.

## Frontend (Node 22)

react 18, react-dom, typescript 5, vite 5, @tanstack/react-query, react-router, zod,
openapi-typescript (types generated from our OpenAPI), tailwindcss, recharts (severity/trend charts),
@testing-library/react + vitest + jsdom, msw (API mocking), eslint + prettier, playwright (M11 E2E).

## Infrastructure

| Image | Notes |
|---|---|
| postgres:16 | pinned digest; named volume |
| redis:7 | queue/broker; no persistence needed |
| ghcr.io/zaproxy/zaproxy:stable | **pinned digest**; `lab` network only; API key required; non-root; read-only rootfs + tmpfs; `cap_drop: ALL`; no docker socket |
| bkimminich/juice-shop | **pinned digest**; `lab` network only; network alias `shop.brakes-vapt.test`; container port 3000 published **only** on `127.0.0.1:3000` for analyst browsing |
| node:22-alpine / nginx:alpine | frontend dev/prod |

Docker Compose topology: `vapt_edge` (frontend, api — the only network with egress, for the one
configured LLM provider), `vapt_core` (`internal: true`: api, worker, postgres, redis), `vapt_lab`
(`internal: true`, subnet **`172.30.10.0/24`**: worker, zap, juiceshop). Worker is dual-homed
`core`+`lab` and receives **no** LLM credentials. Subnet conflict check performed 2026-11-12: free
(host Docker networks hold `172.17.0.0/16`, `172.18.0.0/16`, `172.19.0.0/16`; host LAN
`192.168.1.0/24`); `make lab-check` re-verifies before every `lab-up`.

## External data (optional, offline-first)

EPSS and CISA KEV are **not** fetched at scan time (the worker has no egress). They are imported as
dated snapshot files by an admin action from the `api` container, and `epss_asof` / `kev_asof` are
recorded on every risk score. If no snapshot exists, both inputs are null and the priority formula
degrades deterministically.

## Licence note

OWASP ZAP (Apache-2.0) and Juice Shop (MIT) are fine for internal use. Juice Shop ships deliberately
vulnerable code — it must never be reachable from any non-lab network, which the `internal: true`
topology enforces.
