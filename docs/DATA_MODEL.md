# Database Schema (PostgreSQL 16 / SQLAlchemy 2.0 / Alembic)

Conventions: UUIDv7 primary keys (`id`), `created_at`/`updated_at` timestamptz UTC, soft delete only
where audit requires it (`archived_at`), JSONB for scanner-shaped payloads, native PG enums created
via Alembic, `CHECK` constraints for invariants that must hold even under raw SQL.

## 1. Enums

```
protocol            : http | https
asset_state         : registered | active | archived
scope_rule_kind     : include | exclude
grant_state         : draft | active | expired | revoked
approval_kind       : scan_execution | intrusive_profile | report_export
approval_state      : pending | approved | rejected | expired
discovery_state     : queued | running | completed | failed | cancelled
assessment_state    : discovered | verified | inferred | unassessed
job_state           : queued | preflight | running | paused | cancelling
                    | cancelled | completed | failed | blocked
scan_phase          : preflight | spider | passive | active | collect | normalize
                    | validate | score | done
severity            : informational | low | medium | high | critical
confidence          : low | medium | high | confirmed_by_tool
validation_state    : candidate | confirmed | false_positive | inconclusive | not_applicable
evidence_kind       : http_request | http_response | header_set | dom_snapshot
                    | diff | screenshot | tool_log | reproduction_note
detection_source    : zap_passive | zap_active | zap_spider | discovery | mock | nuclei | manual
actor_kind          : human | system | agent
agent_run_state     : running | completed | failed | halted_by_guard | budget_exceeded
report_state        : draft | generating | ready | failed
```

## 2. Identity, authorisation, audit

```
analysts(id, email unique, display_name, role enum[analyst|approver|admin],
         is_active, created_at)
api_tokens(id, analyst_id FK, token_hash unique, label, scopes text[],
           expires_at, revoked_at, last_used_at)
audit_log(id, occurred_at, trace_id, actor_kind, actor_id, action,
          subject_type, subject_id, outcome enum[allow|deny|ok|error],
          detail jsonb, prev_hash, entry_hash)
  -- entry_hash = sha256(prev_hash || canonical_json(row)) → tamper-evident chain
  -- INSERT only; no UPDATE/DELETE grant for the app role
```

## 3. Assets and scope

```
assets(id, asset_identifier unique,        -- 'MOCK-WEB-001'
       display_name, hostname, protocol, port,
       base_path default '/',
       environment enum[mock_lab] NOT NULL,   -- MVP accepts this value only
       criticality smallint CHECK 1..5,
       state asset_state,
       notes, created_by FK analysts, created_at, updated_at,
       UNIQUE(hostname, port))
  CHECK (environment = 'mock_lab')            -- removed only by a reviewed migration

asset_resolutions(id, asset_id FK, resolved_ip inet, resolver enum[docker_dns|static],
                  observed_at)               -- history of what the hostname resolved to

scope_rules(id, asset_id FK, kind scope_rule_kind,
            host_pattern,                    -- exact host or single-label wildcard
            port int, path_prefix, method_allowlist text[],
            reason, created_by, created_at)
  -- exclude rules evaluated after include rules and always win

scope_grants(id, asset_id FK, state grant_state,
             document_ref,                   -- path/URL of the signed authorisation
             document_sha256,
             requested_by FK, approved_by FK NULL,
             allowed_cidrs cidr[], allowed_ports int[],
             allowed_profiles text[],        -- scan_profiles.key allowlist
             intrusive_allowed bool default false,
             valid_from timestamptz, valid_until timestamptz,
             revoked_at, revocation_reason, created_at)
  CHECK (valid_until > valid_from)

approvals(id, kind approval_kind, state approval_state,
          subject_type, subject_id,          -- e.g. scan_jobs / reports
          scope_grant_id FK NULL,
          requested_by FK, decided_by FK NULL, decided_at,
          justification, decision_note, expires_at, created_at)
  -- intrusive_profile requires decided_by != requested_by (dual control), enforced in service + CHECK via trigger

lab_isolation_checks(id, checked_at, performed_by actor_kind,
                     network_name, probe_results jsonb,  -- per-probe target → blocked/reachable
                     egress_blocked bool, dns_contained bool,
                     passed bool, valid_until timestamptz, detail)
  -- scanner execution gate reads the latest row; stale (valid_until < now) == not passed
```

## 4. Discovery and attack surface

```
discovery_runs(id, asset_id FK, scope_grant_id FK, state discovery_state,
               profile_key, started_at, finished_at,
               pages_seen, requests_made, budget_snapshot jsonb,
               stop_reason, error, trace_id, created_by)

endpoints(id, asset_id FK, first_seen_run_id FK, last_seen_run_id FK,
          url_normalized,                  -- scheme://host:port/path, sorted query keys, no values
          path, method, status_code_last, content_type_last,
          is_api bool, api_style enum[rest|graphql|unknown] NULL,
          requires_auth_guess bool, auth_entry_kind
              enum[login_form|logout|register|password_reset|token_endpoint|oauth|none],
          assessment assessment_state,
          evidence_note, first_seen_at, last_seen_at,
          UNIQUE(asset_id, url_normalized, method))

endpoint_parameters(id, endpoint_id FK, name,
                    location enum[query|path|body|header|cookie],
                    sample_value_redacted, inferred_type, is_required_guess,
                    assessment assessment_state,
                    UNIQUE(endpoint_id, name, location))

forms(id, endpoint_id FK, action_url_normalized, method,
      enctype, has_csrf_token_field bool, is_login_candidate bool,
      assessment assessment_state)
form_fields(id, form_id FK, name, input_type, is_password bool,
            required bool, autocomplete, UNIQUE(form_id, name))

response_headers(id, endpoint_id FK, header_name, header_value_sample,
                 present bool, observed_count int, assessment assessment_state,
                 UNIQUE(endpoint_id, header_name))
```

`assessment_state` is how the inventory distinguishes **discovered** (seen in a response),
**verified** (re-requested and reproduced), **inferred** (deduced, e.g. a parameter named in JS but
never exercised) and **unassessed** (known to exist, not yet examined). It is set by deterministic
discovery code, never by the agent.

## 5. Scanning

```
scan_profiles(id, key unique,               -- 'zap-passive', 'zap-baseline-local'
              display_name, adapter_name, adapter_version_constraint,
              is_intrusive bool, active_scan bool,
              max_requests_per_second numeric, max_concurrent_requests int,
              max_total_requests int, max_duration_seconds int,
              spider_max_depth int, spider_max_children int,
              included_policies jsonb, excluded_rule_ids text[],
              excluded_path_patterns text[],  -- logout, /api/Users delete, etc.
              method_denylist text[] default '{DELETE,PUT,PATCH}',
              created_at)
  -- rows are seeded by migration, not editable through the API in the MVP

scan_jobs(id, asset_id FK, scope_grant_id FK, approval_id FK NULL,
          profile_key FK scan_profiles.key,
          discovery_run_id FK NULL,          -- surface fed into the scan
          state job_state, phase scan_phase,
          idempotency_key unique,
          adapter_name, adapter_version, adapter_handle,   -- ZAP scan/context ids
          scope_decision_id FK,
          cancel_requested_at, pause_requested_at,
          queued_at, started_at, finished_at,
          requests_made, findings_raw_count, stop_reason, error,
          budget_snapshot jsonb, trace_id, created_by FK)

scope_decisions(id, subject_type, subject_id NULL, asset_id FK,
                policy_version, decision enum[allow|deny],
                gate_results jsonb,          -- ordered [{gate, pass, reason}]
                resolved_ips inet[], evaluated_at, actor_kind, actor_id)

scan_job_events(id, job_id FK, at, from_state, to_state, phase,
                message, detail jsonb)       -- full job timeline, append-only

raw_observations(id, job_id FK, asset_id FK,
                 adapter_name, adapter_version, adapter_rule_id,
                 captured_at, payload jsonb,       -- verbatim scanner record
                 payload_sha256, blob_path NULL,   -- large bodies on disk/object store
                 request_sha256, response_sha256)
  -- immutable; never edited by normalisation
```

## 6. Findings, evidence, validation, risk

```
vuln_catalogue(id, key unique,              -- internal vuln class key
               title, category,              -- OWASP ASVS/Top-10 mapped
               cwe_ids text[], default_severity severity,
               cvss_v31_vector NULL, cvss_v31_base numeric NULL,
               remediation_md, references jsonb, catalogue_version)
  -- curated, human-maintained. The only source of default CVSS. Never LLM-written.

findings(id, asset_id FK, job_id FK, catalogue_key FK NULL,
         fingerprint,                       -- see domain/fingerprint.py
         title, category, endpoint_id FK NULL,
         affected_url, http_method,
         severity severity, confidence confidence,
         description_md, remediation_md,
         detection_source detection_source,
         validation_state validation_state default 'candidate',
         validation_rule_id NULL, validation_version NULL,
         first_seen_at, last_seen_at, occurrence_count int default 1,
         suppressed_at NULL, suppression_reason NULL,
         UNIQUE(asset_id, fingerprint))

finding_observations(finding_id FK, raw_observation_id FK, PRIMARY KEY(both))
  -- provenance: every finding traces to ≥1 immutable raw observation

evidence(id, finding_id FK, kind evidence_kind, label,
         content_redacted text NULL, content_sha256,
         blob_path NULL, media_type,
         raw_observation_id FK NULL, collected_at, collected_by actor_kind)

validation_events(id, finding_id FK, at,
                  from_state validation_state, to_state validation_state,
                  rule_id, rule_version, rule_inputs jsonb,
                  evidence_ids uuid[], actor_kind, actor_id,
                  note)
  -- actor_kind='agent' is rejected by a CHECK: agents cannot change validation state

risk_scores(id, finding_id FK, computed_at,
            formula_version,
            cvss_source enum[catalogue|scanner_mapping|analyst] NULL,
            cvss_version NULL, cvss_vector NULL, cvss_base numeric NULL,
            cvss_environmental NULL,
            epss_score numeric NULL, epss_asof date NULL,
            kev_listed bool default false, kev_asof date NULL,
            priority_score numeric,          -- platform score, separate from CVSS
            priority_band enum[p1|p2|p3|p4|p5],
            inputs jsonb,                    -- every input value, for reproducibility
            UNIQUE(finding_id, computed_at))
```

CVSS and priority are **separate columns and separate concepts**: `cvss_*` describes the
vulnerability class; `priority_score` is the platform's prioritisation of *this* finding on *this*
asset given validation state, confidence, exposure, asset criticality, EPSS and KEV. See `risk/`
design in `ROADMAP.md` M7.

## 7. Agent

```
agent_sessions(id, asset_id FK NULL, analyst_id FK, title, created_at, archived_at)
agent_runs(id, session_id FK, state agent_run_state, question,
           graph_version, llm_provider, llm_model,
           started_at, finished_at,
           tool_call_count, token_input, token_output,
           budget jsonb, halt_reason, trace_id)
agent_messages(id, run_id FK, seq, role enum[system|user|assistant|tool],
               content_md, citations jsonb,   -- [{finding_id|evidence_id}]
               created_at)
agent_tool_calls(id, run_id FK, seq, tool_name, arguments jsonb,
                 allowed bool, denial_reason NULL,
                 result_summary, result_sha256, latency_ms, called_at)
agent_suggestions(id, run_id FK, finding_id FK NULL, kind
                 enum[evidence_gap|rescan_request|remediation_note|triage_opinion],
                 body_md, state enum[proposed|accepted|rejected],
                 decided_by FK NULL, decided_at)
  -- the ONLY write path from the agent; nothing here changes a finding until a human accepts it
```

## 8. Reporting

```
reports(id, asset_id FK, state report_state, title,
        scope_grant_id FK, job_ids uuid[], discovery_run_ids uuid[],
        template_key, template_version,
        filter jsonb,                       -- severities/validation states included
        generated_at, generated_by FK, error)
report_sections(id, report_id FK, seq, key, heading, body_md, data jsonb)
report_artifacts(id, report_id FK, format enum[html|pdf|json|md],
                 blob_path, sha256, bytes, created_at)
```

## 9. Indexing and retention

- `findings`: `(asset_id, validation_state, severity)`, `(job_id)`, GIN on `fingerprint`.
- `raw_observations`: `(job_id, captured_at)`, `payload_sha256`; partition by month if volume grows.
- `audit_log`: `(occurred_at)`, `(subject_type, subject_id)`, `(trace_id)`.
- Retention: raw observations and evidence blobs configurable (default: keep indefinitely in dev);
  audit log never pruned in the MVP.
- Evidence and raw bodies are **redacted on write** by a deterministic redactor (auth headers,
  cookies, bearer tokens, password fields) before `content_redacted` is stored; the unredacted body
  lives only in the blob store behind an admin-only endpoint.

---

## 10. Amendments from the approved decision log (2026-11-12)

### 10.1 `operator_identities` (new — ADR-0009)

```
operator_identities(id, analyst_id FK unique, human_label,
                    independence_attested_by FK analysts,   -- admin who attested
                    attested_at, attestation_note,
                    is_active, revoked_at, created_at)
  CHECK (independence_attested_by <> analyst_id)   -- nobody attests their own independence
```
`DUAL_CONTROL_AVAILABLE` is honoured only when ≥2 rows are attested, distinct and active (verified at
startup, re-verified at preflight gate 7).

### 10.2 `approvals` — added columns

```
+ independence_verified bool            -- decided_by != requested_by AND both attested
+ simulated_dual_control bool           -- true when DUAL_CONTROL_AVAILABLE was false
+ requested_token_id FK api_tokens, decided_token_id FK api_tokens
```
`simulated_dual_control = true` rows are rendered as such in the API, UI and report and are never
described as independent human approval.

### 10.3 `evidence` / `raw_observations` — retention and purge (ADR-0011)

```
evidence          + blob_purged_at, purge_policy_version, access_tier enum[redacted|raw]
raw_observations  + payload_purged_at
retention_runs(id, started_at, finished_at, policy_version,
               counts jsonb, pinned_skipped int, actor_kind, error)
```
Purge nulls content and keeps hashes, adapter, rule id and timestamps, so provenance survives the
content. Evidence referenced by a surviving `report_artifacts` row is exempt (pinned).

### 10.4 `agent_tool_calls` — redaction provenance (ADR-0010)

```
+ redaction_version, redaction_report jsonb   -- counts by redacted kind
+ llm_provider, llm_model                     -- resolved from config at call time
```

### 10.5 `scan_jobs` — per-job isolation (ADR-0008)

```
+ session_asserted_empty_at, teardown_confirmed_at
+ daemon_dirty bool default false
```
A `daemon_dirty` job blocks new jobs on that adapter until an admin resets the scanner.

### 10.6 `validation_events` — override semantics (D10)

Already append-only; the amendment is an explicit constraint that no row is ever updated or deleted
(app DB role lacks UPDATE/DELETE on the table, as with `audit_log`), so a human override always
coexists with the original automated result rather than replacing it. Added columns:
`justification` (NOT NULL when `actor_kind='human'`), `actor_token_id`.
