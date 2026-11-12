# ADR-0010: Redaction boundary for everything sent to the LLM

- Status: Accepted (2026-11-12)
- Relates to: D3, ADR-0007, ADR-0011

## Context
Evidence contains credentials, session cookies, bearer tokens, CSRF tokens, API keys and, in a real
engagement, personal data. The `api`/agent component is the only one with egress, to one configured
provider. Anything placed in a prompt leaves the trust boundary and may be retained or logged by the
provider; deletion afterwards does not undo that.

## Decision
A single mandatory choke point: `agent/redaction.py`. **No agent tool returns text that has not
passed through it**, enforced by making the redactor part of the tool-result type (tools return
`RedactedText`, which can only be constructed by the redactor) and by an import-linter rule
forbidding `agent/` from importing raw blob or evidence readers.

Two-stage redaction:

1. **On write** (`normalization/` + `discovery/`): evidence is redacted before it reaches
   `evidence.content_redacted`. Unredacted bodies exist only in the blob store (ADR-0011).
2. **On egress** (`agent/redaction.py`): a second, independent pass over anything bound for a prompt,
   because stage 1 may miss novel formats and because defence in depth is cheap here.

Redacted classes: `Authorization` / `Proxy-Authorization` / `Cookie` / `Set-Cookie` headers; any
header or parameter whose name matches the secret-name pattern set (`token`, `secret`, `passwd`,
`password`, `apikey`, `api_key`, `auth`, `session`, `jwt`, `csrf`, `signature`, `private`);
password-type form fields; JWT-shaped strings; PEM blocks; high-entropy strings ≥32 chars matching
key-ish shapes; email addresses, phone numbers, card-number-shaped digit runs (Luhn-checked) and
national-ID-shaped patterns.

Replacement preserves analytic value without the value itself:
`<redacted:kind=bearer_token,len=182,sha256=9f2a…>`. Length and hash prefix let the agent reason about
presence, reuse and change without seeing content. Byte budgets truncate long bodies with explicit
`<truncated n bytes>` markers.

Also enforced:
- **Fail closed**: a redactor exception yields an empty `RedactedText` plus a tool error, never the
  raw text. Unredactable binary/opaque evidence is replaced by a metadata summary only.
- **No raw blobs, ever**: the agent cannot read `blob_path` content; `get_raw_observation_summary`
  returns adapter, rule id, hashes and a redacted, truncated excerpt.
- **Provenance over content**: the agent is steered to cite ids, so the answer needs no secret values.
- **Auditability**: each `agent_tool_calls` row stores `result_sha256` of the redacted payload and a
  `redaction_report` (counts by kind), so what crossed the boundary is reconstructible.
- **Untrusted-data envelope**: redacted target-derived text is wrapped with an explicit boundary
  marker; the graph has no node that can act on instructions found inside it.
- **MVP data posture**: synthetic Juice Shop evidence only (D11), so no real personal data exists to
  leak during MVP development. The redactor is nevertheless built and tested now, not later.
- **Configurable provider/model**: `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY_ENV` read from the
  environment in exactly one module (`agent/llm/provider.py`). No provider name, model id or
  credential appears anywhere else in the codebase. `LLM_ENABLED=false` disables the agent entirely.

## Consequences
+ A single auditable choke point rather than per-call discipline; the type system carries the rule.
+ Redaction reports make "what did we send?" answerable after the fact.
− Over-redaction will occasionally hide genuinely useful detail (e.g. a reflected payload that looks
  token-like). Mitigation: `kind`, length and hash are retained, and the analyst can always inspect
  the real evidence in the UI — only the LLM is restricted.
− High-entropy heuristics are imperfect in both directions; the pattern set is versioned
  (`redaction_version` stored per tool call) so a change is visible, and the test suite includes
  known-miss cases as explicit `xfail`s rather than silent gaps.
