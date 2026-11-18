# MVP Phase 7 — Analyst dashboard and reporting

Baseline `ac5831d`. The platform now has a **face and a deliverable**: six screens an analyst
drives the whole pipeline from, and a report that a stakeholder can be handed in HTML, JSON or PDF.
Built before phase 6 at the owner's direction. **Still no scan of the live target** — scanner
execution is disabled, the authorisation document is unsigned, and every assessment in this phase
ran in fixture mode.

## 1. What was built

| Area | Delivered |
|---|---|
| Report template | `vapt-standard` 1.0.0 — nine sections: executive summary, scope, methodology, attack surface, vulnerability summary, findings, risk prioritisation, remediation, limitations |
| Assembly | deterministic: reads **only** stored assessment data (jobs, discovery runs, findings, evidence, grant, isolation check) and derives every figure from it |
| Limitations | **derived from what actually happened**, not boilerplate: fixture-mode counts, absence of a live scan, partial-coverage/cancelled counts, candidate and unmapped counts, unauthenticated surface, no active testing, no priority score, no encryption at rest |
| Renderers | JSON and HTML always; PDF via WeasyPrint, recorded as *unavailable with a reason* if its stack is missing — it never fails the report |
| Escaping | every value through `html.escape(quote=True)`; scanner-controlled evidence renders inside `<pre>` as text |
| Evidence pinning | a report pins the evidence it cites **by reference** (`pins_blob=false`); it never copies blobs into the artifact store |
| Dashboard | React/TypeScript SPA: Overview, Assets, Scope, Assessments, Findings, Reports, plus a sign-in and a permanent safety-posture panel |
| Serving | static bundle on nginx, `/api` reverse-proxied to the api's **edge** address, so the browser sees one origin and the api's edge-only binding is untouched |
| Headers | CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` |

## 2. What the dashboard shows an analyst

* **Overview** — counts by validation state, and a containment panel reading the live isolation
  check, scanner-execution posture and the dual-control note verbatim from the API.
* **Scope** — the authorisation document and its state (`unsigned draft` → grant `draft`), the
  include/exclude rules, and a **dry run of all 13 gates** that shows which gates would deny and
  why. Nothing is executed and nothing is contacted.
* **Assessments** — mode (fixture/live) and profile, discovery, attack surface, candidate tests
  (with the intrusive ones marked as needing an approved profile and genuine dual control),
  history with live state polling, cancellation, and a per-job timeline.
* **Findings** — summary, filters, and a detail view carrying provenance (adapter, adapter rule,
  payload digest), the **deterministic rule** that set the validation state, CVSS and its source,
  redaction counts per evidence item, and the full validation history.
* **Reports** — generate with a validation-state filter, inspect the assembled sections, and
  download any artifact.

A denied request is not a toast: the failing gate rows are rendered with their reasons, so the
blocker is legible rather than mysterious.

## 3. Results

Generated from 20 recorded assessments and 12 findings:

| Artifact | Bytes | Notes |
|---|---|---|
| HTML | 35 971 | every value escaped |
| JSON | 76 474 | full structured data, renderer version recorded |
| PDF | 68 402 | real `%PDF-1.7`, text extractable |

`evidence_pinned: 16`, `pins_blob: false`. The limitations section produced, among others:

> 20 of 20 assessment(s) in this report ran in FIXTURE mode: they replay recorded scanner output
> and make no network request to the target.
> No live scan of the target was performed. Scanner execution is disabled and the authorisation
> document is unsigned…
> 3 assessment(s) did not achieve complete coverage (cancelled). Absence of a finding is therefore
> not evidence of absence…

## 4. Invariant I10 — no report represents synthetic findings as real ones

Asserted on **every artifact format**, not just the readable one. For HTML, JSON and the PDF
(read back through `pdftotext`), each must contain:

1. the asset identifier `MOCK-WEB-001`,
2. the `mock_lab` environment label,
3. the exact synthetic-lab statement, and
4. every item of a non-empty limitations section.

An artifact format that is offered but unavailable is a **failure** of this test, never a skip.
I10 is now wired into the invariant registry pointing at
`tests/backend/test_reports_phase7.py`, and `MILESTONE_STATE.json` records P7 as landed, so the
manifest test fails if that assertion is ever skipped.

## 5. Tests

| Suite | Result |
|---|---|
| `tests/backend` (incl. 19 new phase-7 tests) | **129 passed, 1 skipped** (the by-design cancellation-fault skip) |
| `backend/tests/invariants` | **21 passed, 3 skipped** (I5, I11, I12 — phases not yet landed) |
| `scripts/net_verify.sh` | **115/115 probes**, `net_passed: true`, with the real dashboard in place |
| `tests/net` | **56 passed** |
| `tests/lab` | **62 passed** |

New phase-7 assertions beyond I10: template/version recorded; regeneration over identical inputs
is byte-identical once identity and timestamp are removed; the stored artifact digest matches the
served bytes; scanner-controlled markup is escaped (rendered from a *real* report's sections with
the fields poisoned); a missing PDF stack degrades to a recorded reason rather than an exception;
reports pin evidence without copying blobs; the dashboard serves its security headers, proxies the
API on its own origin, **still requires authentication through that proxy**, loads no external
resource, and ships no token or `localStorage` use in its bundle.

## 6. Defects found and fixed

| Defect | Consequence | Fix |
|---|---|---|
| **WeasyPrint installed unpinned against `pydyf` 0.13** | PDF rendering failed with `AttributeError: 'super' object has no attribute 'transform'` — and the graceful path reported it as a *rendering failure*, so it would have shipped as "PDF unavailable" forever | `pydyf`, `cssselect2` and `tinycss2` pinned alongside `weasyprint==62.3`; PDF now renders (68 kB, text-extractable) |
| The finding detail view read `validation_state` and `cvss_base`, which the **detail** endpoint does not return (it returns structured `validation` and `risk`) | the whole screen crashed to a blank page on every finding | read `validation.state` / `risk.cvss.base`; the type now `Omit`s the two fields so the compiler enforces it. A render **error boundary** was added so one bad screen can no longer blank the dashboard |
| `net_verify.sh`'s TCP probe required `python3`, which the nginx-based dashboard image does not have | every frontend network probe would have become `PROBE_ERROR` — the containment check silently losing coverage of the one new component | a busybox-`wget` classifier that maps the error text onto the same errno classes; `NET-B` now checks that **every** `FROM` in each first-party Dockerfile is digest-pinned, including the new multi-stage frontend build |
| That classifier's first version fell through to `REACHABLE` for any unrecognised message | busybox says "Network unreachable", not "Network is unreachable", so five probes reported the frontend as reaching postgres, redis, the proxy and the internet | patterns corrected **and** the default changed to `UNCLASSIFIED`, which fails every probe that reads it: a classifier must never default to a verdict it did not observe |
| nginx tmpfs mounts were root-owned while the container runs as uid 101 | the dashboard container exited immediately (`mkdir /var/cache/nginx/client_temp: permission denied`) | `uid=101,gid=101` on the tmpfs mounts |
| rollup's native parser hit a stack limit on musl | the production bundle could not be built at all | the build stage uses the glibc `node:20.18.1-bookworm-slim` image (digest-pinned); the **served** image is still nginx-on-alpine with no node runtime |
| WeasyPrint wanted a writable font cache on a read-only root filesystem | `Fontconfig error: No writable cache directories` on every import | `XDG_CACHE_HOME=/tmp` (the api's tmpfs) |

## 7. Security posture — unchanged

`scanner_execution_enabled=false`, `zap_adapter_enabled=false`, `active_scan_enabled=false`,
`dual_control.effective=false`, `llm_enabled=false`. `lab/authorisation/MOCK-WEB-001.md` is
**untouched** and still an unsigned draft. The dashboard holds its token in `sessionStorage` for
the tab only, is attached to `vapt_edge` alone, has **no default route**, and proves it: it cannot
reach postgres, redis, the egress proxy or the internet.

The dashboard is **not** a security boundary. Every control it displays is enforced in the API; it
renders decisions, it does not make them. Its reverse proxy adds no authority — an unauthenticated
request through it is still rejected with 401, and that is asserted.

## 8. Limitations

1. **No live scan, still.** Every figure in every report comes from fixture-mode assessments over
   hand-authored ZAP-shaped data. The reports say so, in all three formats.
2. **One asset.** Each screen operates on the first registered asset; there is no asset switcher.
3. **No authentication UI beyond a token.** Tokens are issued out of band by `make db-seed`; there
   is no login form, session renewal, or logout-everywhere.
4. **The dashboard is published over an opt-in loopback forwarder** (`make frontend-publish`,
   deviation D19), not a published port. Nothing is bound to `0.0.0.0`.
5. **PDF rendering depends on native libraries** baked into the api image. Where they are absent
   the artifact is recorded unavailable with its reason — now also pinned so a dependency
   resolution cannot silently break it again.
6. **Report regeneration is deterministic over identical inputs only.** New assessments change the
   content, by design; there is no report versioning or diff.
7. **No scheduled retention purge** (I12 remains due at P8), and evidence is still unencrypted at
   rest (assumption B7).
8. ZAP's daemon is currently marked **dirty** (`reset_failed_at_R3`) from the lab recovery tests
   and requires an operator restart — correct behaviour, and irrelevant to this phase because the
   ZAP adapter is disabled.

**Next: phase 6 — the AI analyst (stage-2 redaction, egress-proxy use, bounded LangGraph, citations),
then phase 8 — hardening.**
