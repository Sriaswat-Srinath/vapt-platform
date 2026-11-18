# MVP Phase 3 — Worker, discovery and the attack-surface inventory

Baseline `9436d85`. The worker is now a **real Celery service, dual-homed `vapt_core` + `vapt_lab`**,
and the attack-surface inventory and candidate-test matrix work end to end. No ZAP call, no scan of
the live target, flags `false`, authorisation untouched and unsigned.

## 1. What was built

| Area | Delivered |
|---|---|
| Worker | Celery on the same digest-pinned-base image, non-root, read-only rootfs, `concurrency=1`, `prefetch=1`, dual-homed `vapt_core`+`vapt_lab` — **no LLM credentials, no proxy variables** |
| Guarded client | `app/worker/http_client.py`: connects to the **pinned IP with an explicit `Host` header**, token-bucket rate limit, request/duration caps, `follow_redirects=False`, per-redirect scope re-validation, `trust_env=False`, cooperative cancellation |
| Extractors | `app/discovery/extractors.py` — pure: URL normalisation (query **keys** kept, **values dropped**), parameter names, auth-entry classification, API detection, form/field parsing, security-header set |
| Inventory | upserts on natural keys; `discovered` → **`verified`** when a surface reappears in a later run; form actions never requested are recorded as **`inferred`** |
| Classification | `app/discovery/classify.py` — deterministic surface→concern matrix, versioned `1.0.0` |
| Schema | 7 new tables (`discovery_runs`, `endpoints`, `endpoint_parameters`, `forms`, `form_fields`, `response_headers`, `candidate_tests`) via `12c327e1de4a` |
| API | discovery runs (start/get/list/cancel), `attack-surface`, `endpoints/{id}`, `candidate-tests` |
| Fixtures | 10 **hand-authored** synthetic responses in `backend/fixtures/mock-web-001/` |

## 2. Two discovery sources, and why

| Source | Network | Gating |
|---|---|---|
| `fixture` (default) | **none at all** | no scan authorisation needed — nothing is contacted |
| `live` | crawls the authorised target | full gate chain at the API **and** re-evaluated by the worker |

The fixtures are **hand-authored, not recorded from Juice Shop**: the authorisation document is
unsigned, so the platform must not contact the target (`CLAUDE.md` rules 6–7). This is what makes the
pipeline demonstrable today without weakening anything, and a test asserts the fixtures declare it.

## 3. Gate 8 now has an authoritative evaluator

The API cannot resolve lab names (no `vapt_lab` route, by design). The worker can. So for a `live`
run the worker **re-evaluates the full 13-gate chain itself**, persists its own `ScopeDecision` with
`actor_kind='system'`, and refuses to send a single request unless that decision allows — and refuses
outright if no pinned IP was produced. The API's earlier decision is provisional with respect to
resolution; the worker's is authoritative. Invariant I2 holds: no request is made without an allow
decision from the component that can actually verify the target.

## 4. Results

**Fixture discovery** (`requests_made=0`, `coverage_complete=true`): **13 endpoints**, 13 parameters,
4 forms, 59 missing security headers recorded, 7 API endpoints, **3 auth entry points**
(`login_form /login`, `register /register`, `login_form POST /rest/user/login`), and
**9 `discovered` + 4 `inferred`**.

**Second run converges**: still 13 endpoints (upsert, not duplicate), and the 9 become **`verified`**.

**26 candidate tests**, matrix `1.0.0`, with injection correctly marked **INTRUSIVE** and routed to
`zap-active-intrusive`; the login surface produces **no brute-force candidate** (asserted by test).

**Live discovery denied**: HTTP 409 at `scanner_execution_enabled`, and **no run row is created**.

**Worker reachability** — reaches what it must and nothing else:
`internet ✗ · egress-proxy ✗ · api ✗ · lab target ✓ · ZAP ✓`, no default route, on no egress network.

**Suites**: `net_verify` **113/113** (5 new probes) · `pytest tests/backend` **53 passed**
(28 discovery/extractor/classification + 25 core).

## 5. Probe-expectation changes (stated, not silent)

| Probe | Before | Now | Why |
|---|---|---|---|
| `NET-A:worker` | `vapt_core` | `vapt_core,vapt_lab` | the ratified phase-3 topology (`NETWORK_ARCHITECTURE.md` §3). Exact-match still proves the worker is on **no egress network**, and new `NET-G10` asserts that directly |
| `NET-B:worker` | registry digest | digest-pinned `FROM` + matching built image id | the worker is now a first-party image |
| `NET-C:worker` | flagged `^LLM_` | flags `*_API_KEY`, `*_TOKEN`, `HTTP(S)_PROXY`, provider names, `LLM_API_KEY/PROVIDER/MODEL/BASE_URL` | **my check was a false positive**: `LLM_ENABLED=false` documents the posture and grants nothing. A new `NET-C:*:llm-off` probe fails if `LLM_ENABLED` is ever true here |
| new | — | `NET-G8`, `NET-G9`, `NET-G10` | the worker must *reach the target and ZAP* and must be on no egress network |

## 6. Defects found and fixed

| Defect | Fix |
|---|---|
| `index("  postgres:")` in my compose patch matched the `depends_on:` entry inside the **api** block, duplicating half the file | restored from git and re-patched against the verbatim worker block; `yaml.safe_load` + `compose config -q` now run before anything else |
| Celery/kombu needed `packaging`, and kombu's redis transport requires `redis>=6.1` while I pinned `5.2.1` | pinned `packaging==24.2`, `redis==6.2.0` |
| A registration page was labelled `login_form` by the auth candidate | surface kind now derives from `auth_entry_kind` (`registration_form`, `token_endpoint`, `oauth_endpoint`) |

## 7. Limitations

1. **No ZAP call yet.** `SCANNER_EXECUTION_ENABLED=false`; the adapter is phase 4.
2. **Live discovery has never run**, so the crawler's behaviour against the real target is
   *implemented and unit-tested*, not field-proven. The guarded client's scope logic is tested
   directly (redirects, exclusions, caps); the end-to-end crawl is not.
3. Fixtures are synthetic and hand-authored — they exercise the extractors, not Juice Shop's real
   markup. Counts from a live run will differ.
4. No JS rendering: SPA routes are found only via links and API responses.
5. Discovery cancellation is checked between fixture items / requests; the bounded-latency figure is
   not yet measured end to end (phase 4, with `CANCELLATION_SLA_SECONDS`).
6. `candidate_tests` are candidates only. Nothing selects or runs them yet.

**Next: phase 4 — ZAP adapter (mock first), global daemon lease, per-job contexts, raw observations,
and the job lifecycle through to a completed passive assessment.**
