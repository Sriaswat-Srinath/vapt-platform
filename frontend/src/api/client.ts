// Typed client for the VAPT API. The token is held in memory and in
// sessionStorage for the tab only; it is never written to localStorage.
export type Role = "analyst" | "approver" | "admin";

export interface Asset {
  id: string; asset_identifier: string; display_name: string; hostname: string;
  protocol: string; port: number; base_path: string; environment: string;
  criticality: number; state: string; notes: string | null; created_at: string;
}
export interface GateResult { gate: string; pass: boolean; reason?: string }
export interface ScopeDecision {
  policy_version: string; decision: "allow" | "deny"; mode?: string;
  gate_results: GateResult[]; resolved_ips: string[]; scope_decision_id?: string;
}
export interface ScopeRule {
  id: string; kind: string; host_pattern: string; port: number | null;
  path_prefix: string; method_allowlist: string[] | null; reason: string | null;
}
export interface Grant {
  id: string; state: string; document_ref: string; document_state: string;
  allowed_cidrs: string[]; allowed_ports: number[]; allowed_profiles: string[];
  intrusive_allowed: boolean;
}
export interface Profile {
  key: string; display_name: string; adapter_name: string; is_intrusive: boolean;
  active_scan: boolean; max_requests_per_second: number; max_total_requests: number;
  max_duration_seconds: number;
}
export interface Job {
  id: string; asset_id: string; profile_key: string; mode: string; state: string;
  phase: string; adapter_name: string | null; pinned_ips: string[] | null;
  coverage_complete: boolean; stop_reason: string | null; queued_at: string | null;
  created_at: string;
}
export interface JobEvent {
  at: string; from_state: string | null; to_state: string; phase: string | null;
  message: string;
}
export interface Finding {
  id: string; title: string; category: string; affected_url: string; http_method: string;
  parameter_name: string | null; severity: string; confidence: string;
  detection_source: string; validation_state: string; validation_rule_id: string | null;
  catalogue_key: string | null; unmapped_rule_id: string | null;
  coverage_complete: boolean; occurrence_count: number; quarantined: boolean;
  cvss_base: number | null; first_seen_at: string; last_seen_at: string;
}
// The detail endpoint does NOT repeat the list's flattened `validation_state`
// and `cvss_base`: it returns the structured `validation` and `risk` objects
// instead, so those two are omitted here rather than typed as present.
export interface FindingDetail extends Omit<Finding, "validation_state" | "cvss_base"> {
  description_md: string | null; remediation_md: string | null; fingerprint: string;
  validation: { state: string; rule_id: string | null; rule_version: string | null };
  risk: {
    cvss: { source: string | null; version: string | null; vector: string | null; base: number | null };
    epss: number | null; kev_listed: boolean; priority_score: number | null;
    formula_version: string | null; note?: string; cvss_reason?: string;
  } | null;
  catalogue: { cwe_ids: string[] | null; default_severity: string; references: unknown; catalogue_version: string } | null;
  provenance: { raw_observation_id: string; adapter: string; adapter_version: string | null; adapter_rule_id: string | null; payload_sha256: string; captured_at: string }[];
  evidence: { id: string; kind: string; label: string; redaction_version: string | null; redaction_report: { counts?: Record<string, number> } | null; has_unredacted_original: boolean; collected_at: string }[];
  validation_history: { at: string; from_state: string | null; to_state: string; rule_id: string | null; rule_version: string | null; actor_kind: string; actor_id: string | null; justification: string | null; note: string | null; rule_inputs: unknown }[];
}
export interface AttackSurface {
  asset: { id: string; asset_identifier: string; hostname: string; port: number; environment: string };
  counts: Record<string, number>;
  by_assessment: Record<string, number>;
  auth_entry_points: { path: string; kind: string; method: string }[];
  endpoints: { id: string; path: string; method: string; status: number | null; content_type: string | null; is_api: boolean; api_style: string | null; requires_auth_guess: boolean; auth_entry_kind: string; assessment: string }[];
}
export interface CandidateTests {
  matrix_version: string | null; note: string;
  candidates: { id: string; path: string | null; surface_kind: string; concern: string; suggested_profile_key: string | null; requires_intrusive: boolean; rationale: string }[];
}
export interface Capabilities {
  scanner_execution_enabled: boolean; zap_adapter_enabled: boolean;
  active_scan_enabled: boolean; default_scanner_adapter: string;
  dual_control: { flag: boolean; attested_distinct_active_identities: number; required: number; effective: boolean; note: string };
  llm_enabled: boolean; evidence_encryption: string; environment_policy: string;
  policy_version: string;
}
export interface CategoryCoverage {
  key: string; display_name: string; tier: number; priority: string;
  assertability: string; owasp_2021: string | null; description: string;
  catalogue_entries: number; decidable_entries: number; candidates: number;
  findings_total: number; findings_by_state: Record<string, number>;
  detection: string; blocked_by: string[]; note: string;
}
export interface Coverage {
  asset_id: string; asset_identifier: string;
  summary: {
    taxonomy_version: string; matrix_version: string; rules_version: string;
    tier1_total: number; tier1_detecting: number; tier1_partial: number;
    tier1_surface_only: number; tier1_catalogued_only: number;
    tier1_no_capability: number; tier1_with_findings: number;
    categories_this_build_cannot_report: string[]; uncategorised_findings: number;
    note: string;
  };
  categories: CategoryCoverage[];
}

export interface AgentProposal {
  id: string; run_id: string; tool: string; arguments: Record<string, unknown>;
  citations: string[]; state: string; reviewed_by: string | null;
  reviewed_at: string | null; review_note: string | null; created_at: string;
  advisory: boolean;
}
export interface AgentRun {
  id: string; asset_id: string; state: string; model: string | null;
  provider_host: string | null; runner_version: string; prompt_version: string;
  tool_catalogue_version: string; boundary_version: string | null;
  boundary_report: { checked_fields: number; re_redacted_fields: number; keyed_refs: number } | null;
  bytes_sent: number | null; bytes_received: number | null; elapsed_ms: number | null;
  error: string | null; rejected: { reason: string; detail: string; tool?: string }[];
  started_at: string; finished_at: string | null; proposals: AgentProposal[];
}
export interface AgentCapabilities {
  llm_enabled: boolean; model: string | null; provider_host: string | null;
  egress: string; runner_version: string; prompt_version: string;
  tool_catalogue_version: string; boundary_version: string;
  tools: { tool: string; summary: string; fields: string[]; requires_citations: boolean }[];
  cannot: [string, string][]; note: string;
}

export interface ChatTurn {
  id: string; role: "user" | "assistant"; content: string; citations: string[];
  tool_calls: { tool: string; arguments: Record<string, unknown>; rows: number }[];
  refusals: { tool: string; reason: string; detail: string }[];
  rounds: number | null; model: string | null;
  input_tokens: number | null; output_tokens: number | null;
  error: string | null; created_at: string;
}
export interface Conversation {
  id: string; asset_id: string; title: string | null; state: string;
  input_tokens: number; output_tokens: number; created_at: string; updated_at: string;
  turns: ChatTurn[];
}
export interface ChatCapabilities {
  enabled: boolean; model: string | null; chat_version: string;
  retrieval_version: string; max_tool_rounds: number;
  conversation_token_budget: number;
  tools: { name: string; description: string }[]; note: string;
}

export interface Report {
  id: string; title: string; state: string; generated_at: string | null;
  template_key: string; template_version: string; filter: { include_states?: string[] } | null;
  artifacts: { format: string; bytes: number; sha256?: string; unavailable_reason: string | null }[];
}
export interface ReportDetail extends Report {
  job_ids: string[] | null; error: string | null; evidence_pinned: number; pins_blob: boolean;
  sections: { seq: number; key: string; heading: string; body_md: string | null; data: Record<string, unknown> }[];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly problem: { type?: string; title?: string; detail?: string; scope_decision?: ScopeDecision; reasons?: string[] },
  ) {
    super(problem.detail || problem.title || `HTTP ${status}`);
  }
}

const TOKEN_KEY = "vapt.token";
let token: string | null = sessionStorage.getItem(TOKEN_KEY);

export function setToken(value: string | null) {
  token = value;
  if (value) sessionStorage.setItem(TOKEN_KEY, value);
  else sessionStorage.removeItem(TOKEN_KEY);
}
export function getToken() { return token; }

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers || {}),
    },
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, body || {});
  return body as T;
}

export const api = {
  health: () => call<{ status: string }>("/system/health"),
  capabilities: () => call<Capabilities>("/system/capabilities"),
  isolation: () => call<Record<string, unknown>>("/system/isolation"),
  scannerState: () => call<Record<string, unknown>>("/system/scanner/state"),
  assets: () => call<Asset[]>("/assets"),
  asset: (id: string) => call<Asset>(`/assets/${id}`),
  registerAsset: (body: Record<string, unknown>) =>
    call<Asset>("/assets", { method: "POST", body: JSON.stringify(body) }),
  scopeRules: (id: string) => call<ScopeRule[]>(`/assets/${id}/scope-rules`),
  grants: (id: string) => call<Grant[]>(`/assets/${id}/scope-grants`),
  validateScope: (id: string, body: { profile_key?: string; path?: string; method?: string }) =>
    call<ScopeDecision & { scope_decision_id: string }>(`/assets/${id}/scope/validate`,
      { method: "POST", body: JSON.stringify(body) }),
  profiles: () => call<Profile[]>("/scan-profiles"),
  jobs: (assetId?: string) => call<Job[]>(`/assessments${assetId ? `?asset_id=${assetId}` : ""}`),
  job: (id: string) => call<Job>(`/assessments/${id}`),
  jobEvents: (id: string) => call<JobEvent[]>(`/assessments/${id}/events`),
  startAssessment: (assetId: string, profileKey: string, mode: "fixture" | "live") =>
    call<Job>(`/assets/${assetId}/assessments?mode=${mode}`,
      { method: "POST", body: JSON.stringify({ profile_key: profileKey }) }),
  cancelAssessment: (id: string) => call<Job>(`/assessments/${id}/cancel`, { method: "POST" }),
  startDiscovery: (assetId: string, source: "fixture" | "live") =>
    call<{ id: string; state: string; source: string; enqueued: boolean }>(
      `/assets/${assetId}/discovery-runs?source=${source}`, { method: "POST" }),
  discoveryRuns: (assetId: string) =>
    call<{ id: string; source: string; state: string; pages_seen: number; stop_reason: string | null; coverage_complete: boolean; created_at: string }[]>(
      `/assets/${assetId}/discovery-runs`),
  attackSurface: (assetId: string) => call<AttackSurface>(`/assets/${assetId}/attack-surface`),
  candidateTests: (assetId: string) => call<CandidateTests>(`/assets/${assetId}/candidate-tests`),
  coverage: (assetId: string) => call<Coverage>(`/assets/${assetId}/coverage`),
  findings: (assetId: string) => call<Finding[]>(`/findings?asset_id=${assetId}&limit=200`),
  finding: (id: string) => call<FindingDetail>(`/findings/${id}`),
  findingsSummary: (assetId: string) =>
    call<{ total: number; by_validation_state: Record<string, number>; by_severity: Record<string, number>; unmapped_detections: number; partial_coverage: number; note: string }>(
      `/assets/${assetId}/findings/summary`),
  evidence: (id: string) =>
    call<{ id: string; kind: string; label: string; redacted: boolean; redaction_version: string | null; content: string | null }>(
      `/evidence/${id}/content`),
  reportTemplates: () =>
    call<{ key: string; version: string; sections: string[] }[]>("/report-templates"),
  chatCapabilities: () => call<ChatCapabilities>("/chat/capabilities"),
  conversations: (assetId: string) =>
    call<Omit<Conversation, "turns">[]>(`/conversations?asset_id=${assetId}`),
  conversation: (id: string) => call<Conversation>(`/conversations/${id}`),
  startConversation: (assetId: string, title?: string) =>
    call<Conversation>(`/assets/${assetId}/conversations`,
      { method: "POST", body: JSON.stringify({ title: title ?? null }) }),
  askQuestion: (conversationId: string, question: string) =>
    call<ChatTurn>(`/conversations/${conversationId}/messages`,
      { method: "POST", body: JSON.stringify({ question }) }),
  agentCapabilities: () => call<AgentCapabilities>("/agent/capabilities"),
  agentRuns: (assetId: string) => call<AgentRun[]>(`/assets/${assetId}/agent/runs`),
  startAgentRun: (assetId: string) =>
    call<AgentRun>(`/assets/${assetId}/agent/runs`, { method: "POST" }),
  reviewProposal: (id: string, decision: "accepted" | "rejected", note?: string) =>
    call<AgentProposal>(`/agent/proposals/${id}/review?decision=${decision}`,
      { method: "POST", body: JSON.stringify({ note: note ?? null }) }),
  reports: (assetId?: string) => call<Report[]>(`/reports${assetId ? `?asset_id=${assetId}` : ""}`),
  report: (id: string) => call<ReportDetail>(`/reports/${id}`),
  generateReport: (assetId: string, includeStates: string[]) =>
    call<Report>(`/assets/${assetId}/reports?include_states=${includeStates.join(",")}`,
      { method: "POST" }),
  // Artifacts need the bearer token, so they are fetched rather than linked, and
  // always saved as a file: report HTML embeds scanner-controlled text (escaped at
  // render time) and is never executed in the dashboard's own origin.
  downloadArtifact: async (reportId: string, fmt: string) => {
    const res = await fetch(`/api/v1/reports/${reportId}/artifacts/${fmt}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const text = await res.text();
      throw new ApiError(res.status, text ? JSON.parse(text) : {});
    }
    const blob = new Blob([await res.arrayBuffer()], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vapt-report-${reportId.slice(0, 8)}.${fmt}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  audit: () => call<{ seq: number; occurred_at: string; actor_kind: string; action: string; subject_type: string | null; outcome: string }[]>("/audit?limit=40"),
};
