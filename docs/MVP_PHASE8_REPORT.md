# MVP Phase 8 — Operational hardening: verification report

Baseline `cd44983`. Four milestones delivered — M8.1 the Gate 2 decision, M8.2 operational
hardening, M8.3 engineering assurance, M8.4 detection validation — with **no change to the
existing safety architecture**. Nothing here enables live scanner execution, and the
authorisation document remains an unsigned draft, untouched since `83497ce`.

---

## M8.1 — The Gate 2 decision

**Decision: both verdicts are required, and they stay separate.** Gate 2 now denies unless
containment passed **and** host hygiene passed **and** the check is fresh.
[ADR-0015](adr/ADR-0015-gate2-requires-host-hygiene.md) records it. `POLICY_VERSION` → **1.1.0**,
so every stored decision says which policy produced it.

A denial now names which half failed:

> gate 2 `lab_isolation_valid`: host hygiene failed: a wildcard host listener is reachable from
> the lab through its gateway (0.0.0.0:5433 [::]:5433). Containment passed, so the scanner cannot
> reach the internet or the LAN, but it could reach that service. Resolve the listener or bind it
> to loopback; do not weaken this gate.

A check reported without a hygiene verdict (`null`) is a **denial**, not a pass: an unknown is not
a yes.

### The investigation, measured rather than reasoned about

From a container on `vapt_lab`:

| Destination | Result |
|---|---|
| host gateway `172.30.10.1:5433` — the foreign listener | **TIMEOUT** (silently dropped) |
| host gateway `172.30.10.1:22` | ECONNREFUSED — proves the host is reachable at L3 |
| `1.1.1.1:443` | ENETUNREACH |
| `172.30.10.20:3000` — the registered target | REACHABLE |

The listener is **not presently reachable** from the lab. **The verdict was not changed.** It is a
property of today's firewall and Docker rules, not a control this project owns, and a check that
passed because a drop happened to be in place would be measuring luck. The measurement is recorded
as new probes `PUB-2R:<port>` which move no verdict, so the owner decides with evidence.

Options for the listener are documented in the ADR. **Another project's service was not removed,
stopped or modified**, and no host firewall rule was added.

Live execution on this machine is therefore now denied at gate 1 (execution disabled), **gate 2
(host hygiene)** and gate 5 (unsigned authorisation).

---

## M8.2 — Operational hardening

### Evidence retention and invariant I12

| Property | How it is enforced |
|---|---|
| Scope | **unredacted blobs only**. Findings, raw observations, evidence rows, provenance digests and the audit log are never purged |
| Eligibility | older than the window **and** zero active references |
| Idempotent | selection is by FACTS about current state — never a cursor or a flag from an earlier run — so a repeat run is a no-op, not a second attempt |
| Halts | **every candidate is verified before any is deleted**, so an inconsistency means the batch deletes *nothing*, not "some, then stopped" |
| Default | `RETENTION_ENABLED=false`; the API endpoint is **dry run unless asked otherwise**, admin only |
| Scheduled | a Celery beat entry that exists only while the flag is true, and the task re-checks the flag before touching anything |

Measured, with real blobs (`make test-retention`):

```
3 synthetic unreferenced blobs → purged 3, bytes reclaimed > 0, state completed
same run again                 → scanned 0, purged 0            (idempotent)
2 good candidates + 1 blob whose FILE is missing
                               → state HALTED, halt_reason blob_file_missing, purged 0
```

The halt is recorded as a `purge_runs` row, which is the point of the invariant: a run that
stopped because the store and the database disagreed is the row you want to find later.

An orphan reference — an evidence row pointing at a blob that does not exist — turns out to be
**impossible to create**: the phase-5 database trigger refuses it. The runtime check stays as
defence in depth against a future schema change, and the test asserts the database's refusal,
which is the stronger guarantee.

### API rate limiting

Per-principal fixed window, two classes (reads 240/min, writes 60/min). The key is a digest of the
bearer token, so one analyst cannot exhaust another's budget; the token is never used as a key and
never logged. `/system/health` and `/system/readiness` are **exempt** — a limiter that can block a
healthcheck can restart the container it is protecting.

Failure mode, stated deliberately: this protects **availability, not a boundary**. When Redis
cannot answer, an in-process counter still applies, so there is never *no* limit, and the response
header says which limiter answered.

---

## M8.3 — Engineering assurance

| Tool | State |
|---|---|
| Ruff | `All checks passed` across backend, tests and scripts |
| mypy | `Success: no issues found in 74 source files` |
| CI | `.github/workflows/ci.yml` — lint, types, the invariant manifest, the code-only tests, and the frontend type check + build |

The rule set is deliberately narrow: pyflakes, correctness-class pycodestyle, bugbear and bandit.
Cosmetic families (import ordering, idiom rewrites, collection-literal style) are **absent on
purpose** — a linter that reformats 300 lines across the safety surfaces to satisfy taste is a
worse trade than one that stays quiet until it finds a defect. Fourteen genuine findings were
fixed (unused imports, an unused variable, an ambiguous name).

mypy is pragmatic overall and **strict on the decision surfaces** — `scope_policy`,
`validation.engine`, `taxonomy`, `coverage`, `agent.boundary`, `agent.tools`, `agent.parsing`,
`retention_rules`, `ratelimit` — where a wrong type would quietly change a decision. Twenty-two
type errors were fixed, including several `None`-attribute paths on denial branches.

CI is honest about what it cannot do: the lab containment probes, the network probes and the
integration suites need a running multi-network deployment, and the workflow says so in its own
comments rather than implying coverage it does not have. The `integration` job is declared for a
self-hosted runner and is disabled by default.

Verified: the CI test selection runs **64 passed, 20 skipped** on a tree with no `.lab-state` and
no reachable API.

---

## M8.4 — Detection validation

### Fixtures now exercise every rule pack that can decide

Eight new synthetic alerts, chosen to drive the previously-dark paths **in both directions**:

| Category | Confirming case | Refusing case |
|---|---|---|
| Cryptographic failures | credentials posted to a cleartext action; token written to `localStorage` | HSTS claimed missing on a response that **sets** it |
| Client-side | DOM sink writes a URL parameter into `innerHTML`; third-party script with no SRI | — |
| Information disclosure | `Server: Express/4.17.1` in a header; session id in a URL | debug-error claim whose string is **absent** from the body |
| Broken access control | — | anti-CSRF claim → `candidate` (no rule can confirm it passively) |

Findings now span **six** categories instead of four, with 23 findings across confirmed,
false positive, not applicable and candidate.

### A rule-pack defect the new fixtures exposed

`header_value` treated **every** header claim as a browser-policy claim, so a leaked
`Server: Express/4.17.1` on a JSON endpoint was dismissed as `not_applicable` — the same reasoning
that correctly dismisses a CSP claim on an API response. A version leak applies to any response.
Fixed by distinguishing browser-policy claims from the rest (`claim_is_browser_policy`), rules
**1.2.0**; the finding is now `confirmed`, and the existing not-applicable behaviour for CSP on
JSON is unchanged.

### The evaluation dataset

`backend/fixtures/evaluation/detection_cases.json` — 19 cases, each naming the taxonomy category,
the scenario, the **ground truth**, the expected verdict and why. `scripts/detection_eval.py`
runs it against the live platform and writes [DETECTION_EVALUATION.md](DETECTION_EVALUATION.md)
plus machine-readable JSON.

```
cases 19 · TP 11 · TN 5 · OK 3 · FP 0 · FN 0 · unmatched 0
```

**What that score is not.** Every case is a hand-authored alert over a hand-authored response, so
this measures the pipeline's self-consistency against constructed evidence — **not** real-world
detection accuracy. The dataset says so in its own header, the generated report repeats it, and a
test asserts that the disclaimer is present. A test also asserts the dataset covers both
directions for every deciding rule pack, because a dataset of true positives cannot detect an
over-eager engine.

---

## Verification

| Check | Result |
|---|---|
| `tests/backend` + invariants | **254 passed, 5 skipped** |
| Invariant manifest | **24 passed, 0 skipped** — all fourteen invariants implemented |
| `make test-retention` (I12, destructive) | **4 passed** |
| `make test-agent` (live agent path) | **39 passed** |
| `scripts/net_verify.sh` | **115/115**, `net_passed: true` |
| `make lint` / `make typecheck` | clean |
| `make detection-eval` | 19 cases, 0 FP, 0 FN |
| `tests/lab` + `tests/net` | see §Regression below |

Invariant **I12** is now implemented; all fourteen have a test. Its two destructive cases need
`make test-retention` and **skip with that instruction** otherwise rather than passing vacuously —
recorded in the registry so it cannot be mistaken for full automatic coverage.

---

## Defects found and fixed

| Defect | Consequence | Fix |
|---|---|---|
| **Reference counting ignored report artifacts and raw observations** | a dry run with a zero-day window found **124 "unreferenced" blobs** — which were generated report artifacts and scanner provenance. A real purge would have deleted every stored report and the bytes revalidation re-reads | all four reference classes counted (evidence rows, report pins, raw observations, report artifacts); eligible is now 0, which is the honest answer |
| **Revalidation would silently use less evidence** after a purge | a historical assessment could be re-validated from fewer bytes and reach a *different* verdict with no indication why | revalidation now **refuses** with 409 when any required blob is gone |
| **`header_value` dismissed non-browser header claims** | a leaked server version on a JSON endpoint was reported `not_applicable` | browser-policy claims distinguished from the rest; rules 1.2.0 |
| **Retention env vars were never passed to the containers** | `RETENTION_ENABLED=true` on the host had no effect; the feature looked broken | wired in compose for api and worker, defaulting false |
| Purge deleted some blobs *then* halted | a half-applied batch is harder to reason about and to resume | verification is now a separate phase over the whole batch before anything is removed |

---

## Limitations — unchanged where they matter

1. **No live scan has ever run.** Everything in M8.4 validates the pipeline against constructed
   evidence. M9 remains the real milestone.
2. **Gate 2 now blocks live execution on this machine** until the foreign listener is resolved by
   its owner. That is the decision working, not a defect.
3. **Retention is off by default** and has never run against real aged data; the window is 90 days
   and nothing in the store is that old.
4. **Rate limiting is per-principal and per-process-window.** It is not a defence against a
   distributed flood and is not claimed to be.
5. **CI cannot verify containment.** Only the machine running the lab can, and the workflow says so.
6. **The I12 destructive cases are opt-in.** They skip by default with instructions.
7. Evidence is still unencrypted at rest; dual control is still unavailable with one operator; the
   seven Tier-1 categories needing active testing are still surface-only.

**Next: M9 — the first genuine passive assessment**, which needs, in order: a human signature on
`lab/authorisation/MOCK-WEB-001.md`, the Gate 2 listener resolved, an independent review of the
scanner configuration and containment, then the separate decisions to enable scanner execution and
the ZAP adapter with active scanning left off.
