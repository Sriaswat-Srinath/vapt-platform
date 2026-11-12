# Data Flow: selecting an asset → vulnerability report

Numbered steps map to the modules that own them. "⛔" marks a deterministic gate that can stop the
flow; "📝" marks an audit-log write.

## Phase 1 — Asset selection and authorisation

1. Analyst opens **Registered Assets**, selects `MOCK-WEB-001` (`shop.brakes-vapt.test:3000`).
   `GET /assets/{id}` returns the asset, its scope rules and the state of its scope grants.
2. The UI shows whether scanning is currently possible: `GET /system/capabilities` +
   `GET /system/isolation`. If `SCANNER_EXECUTION_ENABLED=false` or the isolation check is
   failed/stale, the scan controls are disabled with the reason shown. ⛔
3. If no active grant exists: analyst creates a `scope_grant` draft referencing the written
   authorisation document (path + SHA-256); an **approver** activates it. 📝 Intrusive profiles
   additionally need an `approvals` row decided by a second person.

## Phase 2 — Attack-surface discovery

4. Analyst starts a discovery run. `services/discovery_service` builds an immutable `ScopeRequest`
   and calls `safety.preflight.evaluate()`. The resulting `ScopeDecision` is persisted. ⛔📝
5. On `allow`, a `discovery_runs` row is created `queued` and a Celery task is enqueued with the job
   id only (no payload trust). The worker claims it under a per-asset advisory lock.
6. The crawler requests the pinned IP with the correct `Host` header, honouring the token-bucket rate
   limit, concurrency semaphore, request cap and timeouts. Redirects are not auto-followed: each
   `Location` is re-validated by `redirect_guard`; out-of-scope ones are dropped and counted. ⛔📝
7. Extractors parse each response into: `endpoints` (URL, method, status, content type), 
   `endpoint_parameters` (query/path/body/header/cookie), `forms` + `form_fields`,
   `response_headers`, API endpoints (JSON/`/api/` heuristics, GraphQL probe), and auth entry points
   (login/logout/register/reset/token). Each record gets `assessment` = `discovered` | `verified`
   (re-requested and reproduced) | `inferred` (named in JS/docs but never exercised) | `unassessed`.
8. `discovery/inventory.py` upserts on the natural keys so repeat runs converge rather than
   duplicate; the run ends `completed` (or `completed` with `stop_reason='budget_exhausted'`).
   The **Attack Surface** page reads this inventory.

## Phase 3 — Vulnerability scanning

9. Analyst picks a `scan_profile` (`zap-passive` by default) and starts a scan.
   The full preflight chain runs again — including profile allowlist, intrusive approval, resolution,
   port, scope rules, concurrency and no-conflicting-job. ⛔📝
10. `scan_jobs` row created `queued` with an `idempotency_key`; worker claims it, moves to
    `preflight` → `running`, and resolves the adapter from `scanners/registry` (`mock` unless ZAP is
    explicitly enabled).
11. The adapter receives a `ScanJobSpec` built **only** from the persisted allow-decision: pinned IPs,
    profile budgets, excluded path patterns, rule denylist, and seed URLs taken from the discovery
    inventory. The adapter re-checks the decision before starting. ⛔
12. ZAP phases run: context creation → spider (depth-capped) → passive queue drain → active scan
    *only if the profile and approval permit* → collect. `poll()` drives
    `scan_job_events` + progress; pause/cancel requests are honoured at every phase boundary; budget
    exhaustion stops the job with a valid partial result. 📝
13. `collect()` returns verbatim alerts and request/response messages. Each becomes one immutable
    `raw_observations` row with payload hashes; large bodies go to the blob store. Nothing is
    interpreted at this stage.

## Phase 4 — Normalisation

14. `normalization/mapper.py` maps each raw observation to a `NormalizedFinding` via the versioned
    ZAP mapping (plugin id → catalogue key, risk → severity, confidence → confidence). Unmapped
    plugin ids are kept with a null catalogue key and surfaced separately — never dropped.
15. `normalization/dedup.py` computes the fingerprint and upserts `findings`
    (`UNIQUE(asset_id, fingerprint)`): new → insert as `candidate`; repeat → increment
    `occurrence_count`, refresh `last_seen_at`, link the new observation. Out-of-scope URLs are
    discarded with an audit entry. ⛔📝
16. Request/response pairs, header sets and relevant snippets are written to `evidence`, redacted on
    write, each linked back to its raw observation → every finding has provenance.

## Phase 5 — Deterministic evidence validation

17. `validation/engine.py` loads the rule pack for each finding's category and evaluates predicates
    over the stored evidence only. Examples:
    - *missing security header*: header absent across ≥N successful responses on ≥M distinct URLs ⇒
      `confirmed`; present on some ⇒ `inconclusive`; endpoint non-HTML/non-browser-reachable ⇒
      `not_applicable`.
    - *reflected input*: payload echoed unencoded in an HTML context with `text/html` ⇒ `confirmed`;
      echoed but encoded ⇒ `false_positive`; echoed in a non-HTML context ⇒ `inconclusive`.
    - *verbose error / info leak*: pattern matched in body AND status ≥500 ⇒ `confirmed`.
    - missing required evidence ⇒ stays `candidate` with the gap recorded.
18. Every transition writes a `validation_events` row carrying `rule_id`, `rule_version`,
    `rule_inputs` and the `evidence_ids` relied on. Agents are rejected as actors by a CHECK. 📝

## Phase 6 — Risk assessment

19. `risk/cvss.py` attaches CVSS from the curated `vuln_catalogue` (or an explicit scanner mapping),
    recording `cvss_source`. No CVSS is ever generated by the LLM.
20. `risk/priority.py` computes `priority_score` = versioned function of normalised severity,
    confidence, validation state (a `candidate` or `inconclusive` finding cannot outrank an equivalent
    `confirmed` one), exposure (auth required? API? reachable surface), asset criticality, EPSS and
    KEV. All inputs are stored in `risk_scores.inputs` with `formula_version` so any score is
    reproducible and explainable field-by-field in the UI.

## Phase 7 — Analyst investigation

21. **Findings** and **Finding Detail** pages read findings, evidence, provenance, validation history
    and risk breakdown. The analyst may set a classification *with justification* — recorded as a
    human `validation_event`, never overwriting the engine's history.
22. The analyst asks the **AI Assistant** about a finding or the scan. The LangGraph run retrieves
    only via allowlisted read tools scoped to the asset, explains technical and business impact,
    lists missing evidence, and proposes remediation. Suggestions land in `agent_suggestions` as
    `proposed`; nothing changes until a human accepts. Tool calls, budgets and guard verdicts are
    persisted. 📝

## Phase 8 — Reporting

23. Analyst requests a report for the asset and a set of jobs. `reporting/assembler.py` reads only
    stored, deterministic data and builds sections: executive summary (computed counts and bands,
    template-driven prose), scope (asset, grant, approvals, allowed CIDRs/ports/profiles), scan
    methodology (adapter + version, profile budgets, phases, what was excluded and why), discovered
    attack surface, vulnerability summary, individual findings with evidence and provenance, risk
    prioritisation (CVSS vs priority side by side), remediation recommendations, and **limitations**
    (unauthenticated-only, passive-only, budget-exhausted jobs, unmapped detections, inconclusive
    findings, mock-environment caveat).
24. Renderers emit HTML → PDF and JSON; artifacts are hashed and stored in `report_artifacts`.
    Export is audit-logged. 📝 Any agent-authored prose included in a report is labelled as
    AI-generated and must carry its citations.

## Failure and resumption semantics

- Any phase can be retried: raw observations are immutable and keyed by hash, normalisation and
  validation are idempotent functions of stored inputs, so re-running produces the same rows.
- A cancelled or budget-exhausted job still flows through phases 4–6 for whatever it collected, and
  the report marks coverage as partial.
- A revoked or expired grant immediately blocks new runs; in-flight jobs are cancelled at the next
  phase boundary with `stop_reason='grant_revoked'`.
