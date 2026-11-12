# API Structure (FastAPI, `/api/v1`)

Transport: JSON over HTTP. Auth: `Authorization: Bearer <api token>`; roles `analyst`, `approver`,
`admin`. OpenAPI 3.1 served at `/api/v1/openapi.json`; frontend types are generated from it
(`scripts/gen_openapi_types.sh`) so the client cannot drift.

Conventions
- Cursor pagination: `?limit=&cursor=` → `{items, next_cursor}`.
- Errors: RFC 9457 problem+json — `{type, title, status, detail, trace_id, errors[]}`.
- Every state-changing call accepts `Idempotency-Key`.
- Scope denials return **409 `scope_denied`** with the full ordered `gate_results` array, never a
  bare 403, so the UI can show exactly which gate failed and why.
- `412 precondition_failed` when `SCANNER_EXECUTION_ENABLED=false` or the lab isolation check is
  stale/failed.

## System
```
GET  /system/health                  liveness
GET  /system/readiness               db, redis, adapter, isolation-check status
GET  /system/capabilities            enabled adapters, profiles, feature flags, versions
GET  /system/isolation               latest lab_isolation_check
POST /system/isolation/verify        admin: re-run egress probe
```

## Assets and scope
```
GET    /assets                       filter: state, environment
POST   /assets                       register mock asset (analyst)
GET    /assets/{asset_id}
PATCH  /assets/{asset_id}            display_name, criticality, notes only
POST   /assets/{asset_id}/archive

GET    /assets/{asset_id}/scope-rules
POST   /assets/{asset_id}/scope-rules
DELETE /scope-rules/{id}

GET    /assets/{asset_id}/scope-grants
POST   /assets/{asset_id}/scope-grants        draft grant (document_ref + sha256 required)
POST   /scope-grants/{id}/activate            approver only; validates document hash
POST   /scope-grants/{id}/revoke
POST   /assets/{asset_id}/scope/validate      dry-run: returns ScopeDecision without side effects

GET    /approvals?state=pending
POST   /approvals                             request approval
POST   /approvals/{id}/decide                 approver; dual control for intrusive_profile
```

## Discovery and attack surface
```
POST   /assets/{asset_id}/discovery-runs      body: {profile_key}
GET    /discovery-runs/{id}
POST   /discovery-runs/{id}/cancel
GET    /assets/{asset_id}/attack-surface      aggregated inventory + counts by assessment
GET    /assets/{asset_id}/endpoints           filter: method, is_api, assessment, auth_entry_kind
GET    /endpoints/{id}                        parameters, forms, headers
GET    /assets/{asset_id}/attack-surface/export?format=json|csv
```

## Scans
```
GET    /scan-profiles
POST   /assets/{asset_id}/scans               body: {profile_key, discovery_run_id?, approval_id?}
                                              → 201 queued | 409 scope_denied | 412 disabled
GET    /scans?asset_id=&state=                scan history
GET    /scans/{id}                            state, phase, progress, budget usage
GET    /scans/{id}/events                     full timeline
POST   /scans/{id}/pause
POST   /scans/{id}/resume
POST   /scans/{id}/cancel
GET    /scans/{id}/raw-observations           admin/analyst; paginated, redacted
```

## Findings, evidence, validation, risk
```
GET    /findings?asset_id=&job_id=&severity=&validation_state=&category=&q=
GET    /findings/{id}                         + evidence, provenance, risk, validation history
GET    /findings/{id}/evidence
GET    /evidence/{id}/content                 redacted body; ?raw=true requires admin
GET    /findings/{id}/validation-history
POST   /findings/{id}/revalidate              re-runs the deterministic engine (no manual override)
POST   /findings/{id}/analyst-classification  analyst sets state WITH required justification;
                                              recorded as a validation_event, actor_kind=human
POST   /findings/{id}/suppress                justification required
GET    /findings/{id}/risk
POST   /findings/{id}/risk/recompute
GET    /assets/{asset_id}/risk-summary        bands, counts, trend
```

## Agent
```
POST   /agent/sessions                        {asset_id?, title}
GET    /agent/sessions
GET    /agent/sessions/{id}/messages
POST   /agent/sessions/{id}/ask               {question, finding_ids?, job_id?}
                                              → SSE stream of tokens + tool-call events
GET    /agent/runs/{id}                       budgets, tool calls, halt reason
GET    /agent/runs/{id}/tool-calls
GET    /agent/suggestions?state=proposed
POST   /agent/suggestions/{id}/decide         analyst accepts/rejects
GET    /agent/tools                           the registered tool catalogue (introspection)
```

## Reports
```
GET    /report-templates
POST   /assets/{asset_id}/reports             {template_key, job_ids, filter}
GET    /reports?asset_id=
GET    /reports/{id}                          sections as structured JSON
GET    /reports/{id}/artifacts
GET    /reports/{id}/artifacts/{artifact_id}/download
POST   /reports/{id}/regenerate
```

## Audit
```
GET /audit?subject_type=&subject_id=&actor_kind=&from=&to=&trace_id=
GET /audit/verify        admin: recompute the hash chain, report first divergence
```

## Response shape examples

```jsonc
// 409 on an out-of-scope scan request
{
  "type": "https://vapt.local/problems/scope-denied",
  "title": "Scan request denied by scope policy",
  "status": 409,
  "detail": "Gate 'target_resolution' failed",
  "trace_id": "01JC…",
  "scope_decision": {
    "policy_version": "1.0.0",
    "decision": "deny",
    "gate_results": [
      {"gate": "asset_registered",      "pass": true},
      {"gate": "environment_is_mock",   "pass": true},
      {"gate": "grant_active",          "pass": true},
      {"gate": "profile_allowed",       "pass": true},
      {"gate": "target_resolution",     "pass": false,
       "reason": "shop.brakes-vapt.test resolved to 93.184.216.34, outside allowed_cidrs"}
    ]
  }
}
```

```jsonc
// GET /findings/{id} (abridged)
{
  "id": "…", "title": "Missing Content-Security-Policy header",
  "category": "security_misconfiguration",
  "affected_url": "http://shop.brakes-vapt.test:3000/", "http_method": "GET",
  "severity": "medium", "confidence": "high",
  "detection_source": "zap_passive",
  "validation": {"state": "confirmed", "rule_id": "missing-security-header", "rule_version": "1.2.0"},
  "risk": {"cvss": {"source": "catalogue", "version": "3.1", "base": 6.1, "vector": "CVSS:3.1/…"},
           "epss": null, "kev_listed": false,
           "priority_score": 58.4, "priority_band": "p3", "formula_version": "1.0.0"},
  "provenance": [{"raw_observation_id": "…", "adapter": "zap", "adapter_version": "2.15.0",
                  "adapter_rule_id": "10038"}],
  "evidence_count": 3
}
```
