# Implementation Risks

Ordered by expected pain. Each has the mitigation I plan to build.

## Safety-critical

1. **Isolation believed but not real.** A misconfigured compose file or a host-level route could give
   the scanner egress. → L1 network design *plus* an active egress probe recorded in
   `lab_isolation_checks`; scanning is gated on a fresh pass, and the gate is tested.
2. **DNS rebinding / split-horizon.** A hostname that validates at preflight but resolves elsewhere at
   request time. → resolve once, pin IPs into the job, connect to the pinned IP with an explicit
   `Host` header, re-validate every redirect.
3. **Scope bypass via redirects or scanner-internal requests.** ZAP follows redirects itself. → ZAP
   context include/exclude regexes as a second barrier, plus post-hoc rejection of any finding whose
   URL is out of scope (audited, not silent).
4. **Prompt injection from scanner output.** Juice Shop content and alert text enter the agent
   context. → agent has no network/shell/write tools at all, untrusted-data envelopes, output guard,
   and a graph with no node capable of acting on retrieved instructions.
5. **Privilege creep into the LLM.** Convenience pressure to let the agent "just mark this a false
   positive". → DB-level CHECK on `validation_events.actor_kind`, import-linter boundaries, guard
   field stripping, and a dedicated test suite that asserts each forbidden write fails.
6. **Approval theatre.** A grant that exists but authorises nothing real. → grant stores the
   authorisation document's SHA-256 and the gate re-verifies it; intrusive profiles need dual control.
7. **Juice Shop self-harm.** The spider can hit destructive endpoints (delete basket, logout, change
   password) and wedge the target. → method denylist, excluded path patterns, passive-first profiles,
   and a one-command lab reset (`make lab-reset`) treating the target as disposable.

## Correctness

8. **False-positive flood from ZAP passive rules.** → deterministic validation rule packs with
   explicit `inconclusive`/`not_applicable` outcomes; the dashboard defaults to hiding unconfirmed
   candidates; "unmapped detections" are reported separately rather than inflating severity counts.
9. **Dedup fingerprint too loose or too tight.** Too loose merges distinct issues; too tight explodes
   counts per payload. → property tests with hypothesis over URL/param permutations, and the
   fingerprint definition is versioned so a change can be migrated deliberately.
10. **Missing CVSS for many ZAP rules.** → curated `vuln_catalogue` is the only default source;
    missing entries leave CVSS null and the priority formula still produces a defensible score.
    Nulls are visible in the UI and the report, never zero-filled.
11. **Assessment-state drift.** `discovered` vs `verified` vs `inferred` is easy to apply sloppily. →
    single code path in `discovery/classify.py`, each state requires a recorded evidence note.

## Operational

12. **Cancellation that doesn't cancel.** Celery `revoke` does not stop a ZAP scan. → cooperative
    cancellation flags polled at phase boundaries + adapter `cancel()` whose result must confirm the
    scanner is idle, otherwise the job fails loudly.
13. **Long-running job state loss on worker restart.** → job state lives in Postgres, adapter handles
    (ZAP context/scan ids) are persisted, a reconciler on worker startup re-attaches or fails jobs
    explicitly rather than orphaning them.
14. **ZAP flakiness and version drift.** The REST API changes between releases. → digest-pinned image,
    recorded fixtures for normalisation tests, and a nightly contract test against the pinned image
    that is allowed to fail independently of unit CI.
15. **`.test` hostname resolution confusion.** It resolves inside `lab` only; developers will try it
    from the host and see failures. → documented in `lab/README.md`; host access is via the published
    port; the isolation check asserts containment rather than reachability.
16. **Report rendering weight.** WeasyPrint adds heavy system libs. → PDF generation isolated in the
    api image, HTML/JSON always available so a PDF failure never blocks reporting.
17. **LLM cost, latency and nondeterminism.** → deterministic pre-summarisation, per-run token/step
    budgets, temperature 0, a `fake` provider used by every test, prompt hashes stored per run.
18. **Evidence storage growth and secret leakage.** Request/response bodies contain tokens. → redact
    on write, blob store for raw bodies behind an admin-only endpoint, configurable retention.

## Process

19. **Milestone creep / safety features deferred "until later".** → M3 (scope and safety) lands before
    any real scanner execution; the mock adapter is the default so M4–M7 can complete with ZAP still
    disabled.
20. **Single-developer bus factor on the safety layer.** → `tests/safety/` is the contract; it is
    table-driven and must be green for any merge, so the rules are readable as data.
