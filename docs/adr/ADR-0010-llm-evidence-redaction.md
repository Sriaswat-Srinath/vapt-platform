# ADR-0010: Redaction boundary for everything sent to the LLM

- Status: Accepted (2026-11-12); **amended R2 (2026-11-12)**
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
`<redacted:kind=bearer_token,len=182,sha256=9f2a…>` — **superseded by Amendment R2 §7: a plain digest
of a secret value is brute-forceable and must not be exposed; keyed HMAC refs replace it.** Length and
reference let the agent reason about
presence, reuse and change without seeing content. Byte budgets truncate long bodies with explicit
`<truncated n bytes>` markers.

Also enforced:
- **Fail closed**: a redactor exception yields an empty `RedactedText` plus a tool error, never the
  raw text. Unredactable binary/opaque evidence is replaced by a metadata summary only.
- **No raw blobs, ever**: the agent cannot read `blob_path` content; `get_raw_observation_summary`
  returns adapter, rule id, hashes and a redacted, truncated excerpt. **Superseded by R2 §8: keyed
  refs only — no plain content hashes cross the boundary.**
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

---

## Amendment R2 (2026-11-12) — keyed correlation identifiers, structural coverage, no indirect path

### 7. Keyed HMAC identifiers replace SHA-256 prefixes of secret values

**Why the original was wrong.** `<redacted:…,sha256=9f2a…>` publishes an unsalted digest of the secret
itself. Secrets with low or moderate entropy — passwords, PINs, short API keys, predictable session
ids, anything from a wordlist — are recoverable offline from such a prefix. The marker leaked the
value it was meant to protect, and it leaked it to the component with egress.

**Decision.** Correlation identifiers are keyed:

```
ref = base32( HMAC-SHA256(key = REDACTION_HMAC_KEY, msg = canonical(secret_value)) )[0:12]
marker = <redacted:kind=bearer_token,len=182,ref=hmac:v1:7C1F9A42K3QM>
```

- The key is read from the env var named by `REDACTION_HMAC_KEY_ENV`, is per-deployment, **never
  leaves the api container, is never logged, never audited and never sent to the provider**.
- `v1` is `REDACTION_KEY_ID`. Rotation mints a new id; historical refs keep their old id and simply
  stop correlating with new ones. That loss is accepted and documented, not worked around (which
  would require retaining the secrets).
- Without the key, a ref is not invertible and not comparable across deployments. With it, the agent
  can still answer "is this the same token as in the other response?", "did it change between
  requests?", "is it reused across endpoints?" — the analytic value the hash was there for.
- `len` and `kind` are retained; a length alone is not a credential.

### 8. Content-integrity hashes are a separate, non-exported concern
- `evidence.content_sha256` (unredacted original) and `redacted_sha256` exist for **integrity and
  provenance**, computed and compared internally. They are *not* correlation identifiers.
- **Rule:** plain SHA-256 values are never placed in an LLM-bound payload. Anything crossing the
  redaction boundary carries keyed `ref` values only. The rule is absolute rather than
  "unless the content is large", because an evidence body may consist solely of a token.
- `get_raw_observation_summary` is amended accordingly: it returns adapter, version, rule id, byte
  counts, keyed refs and a redacted excerpt — **not** `payload_sha256`, `request_sha256` or
  `response_sha256`.
- Integrity verification (`blob content == content_sha256`) runs in the api/worker, never in a prompt.

### 9. Structural redaction coverage (required tests, M8)

Redaction is **structure-aware**: parse, walk, redact leaf values, re-serialise. Regex over raw text
is the fallback for unparseable input, never the primary mechanism.

| Context | Mechanism | Test obligations |
|---|---|---|
| JSON objects and **nested arrays** | recursive walk over dicts/lists to a bounded depth; key-name matching plus value shape matching | secrets at depth ≥5, inside arrays of objects, arrays of arrays, keys differing only by case/underscores, duplicate keys, JSON embedded as a string value |
| URL query parameters | `urlsplit` + `parse_qsl`, redact by parameter name and by value shape, re-encode | secret in query, in fragment, in path segment, repeated parameters, array-style `a[]=`, semicolon separators, percent-encoded names |
| HTML forms | HTML parse; redact `input[type=password]`, secret-named fields, hidden CSRF/state fields, `value` attributes | login form, hidden token, pre-filled value, attribute spread across quoting styles, malformed HTML |
| Multipart forms | per-part walk: part headers, `name`, `filename`, and body | secret in a part body, in a `filename`, in a part header, binary part (metadata-only summary), nested multipart |
| XML | element-tree walk over text nodes **and attributes**; namespace-insensitive name matching | secret in text, in an attribute, in CDATA, in a comment, SOAP header; entity-expansion limits enforced |
| Exception messages | exception type + `args` scrubbed through the redactor; message templates preferred | adapter raising an exception whose text embeds a response body or an `Authorization` header |
| Tool errors and stack traces | error objects are `RedactedText` too; **local variables are never rendered** (`locals` suppressed; frames limited to file/line/function) | a traceback whose frame once held a token; a chained `__cause__`; an error path inside the redactor itself |
| Recognisable encoded credentials | decode-then-scan with bounded passes (default 2): base64 / base64url (incl. `Basic ` payloads and JWT segments), percent-encoding, hex, HTML entities, unicode escapes; the **encoded span** is redacted, not just the decoded text | `Basic` header, JWT header.payload.signature, double-encoded token, hex-encoded key, token inside a base64 JSON blob, non-credential base64 (must survive unredacted — tested both directions) |

Cross-cutting: canary secrets are seeded into every fixture, and a sweep asserts **no canary value
appears in any LLM-bound payload, tool result, prompt log or error** across the whole tool catalogue.
Known gaps are recorded as explicit `xfail`s with a comment, never as silent misses.

### 10. No direct **or indirect** path to raw evidence

Enumerated and closed, each with a test:

| Path | Closure |
|---|---|
| Blob read | `agent/` cannot import blob or raw-evidence readers (import-linter); no tool exposes `blob_path` |
| Raw observation payload | summary tool returns redacted excerpt + keyed refs only |
| DB access | `agent/` has no session, no repository, no engine import |
| Network / shell / filesystem | no such tool; no `httpx`/`subprocess`/`open` import permitted in `agent/` |
| Exception leakage | all tool errors constructed as `RedactedText`; locals suppressed; a bare `str` raised inside a tool is caught and re-wrapped |
| Log / audit retrieval | no tool reads logs, audit rows or `redaction_report`s |
| Report retrieval | no tool reads report artifacts (which could embed evidence) |
| Type bypass | the LLM client's signature accepts **only** `PromptEnvelope[RedactedText]`; a plain `str` raises at runtime, tested |
| Prompt templates | templates interpolate `RedactedText` only; a template rendering a raw object fails CI |
| Streaming echo | model output is not a retrieval path, but the guard still scans it for canaries before persistence |

`RedactedText` is constructible only inside `agent/redaction.py` (module-private constructor plus a
`__init_subclass__` guard), so "forgot to redact" is a type error rather than a review miss.

### Consequences of R2
+ The marker no longer leaks the secret; correlation survives.
+ Coverage is defined by parser, not by hope, and tested in both directions (redacts secrets, does
  not mangle benign data).
− One more secret to manage (`REDACTION_HMAC_KEY`); losing it loses historical correlation only.
− Structural parsing of hostile input needs resource limits (depth, size, entity expansion); these are
  configured and tested, and a parser failure falls back to whole-value redaction, never passthrough.

---

## Amendment R3 (2026-11-12) — HMAC key management

1. **Key material exists only in environment-provided secrets.** `REDACTION_HMAC_KEY_ENV` names the
   variable; the value is loaded once into a `SecretBytes` whose `__repr__`, `__str__` and
   `__format__` return `<redacted>`. It is never written to the database, never to a file, never to an
   artifact.
2. **Every reference records key id and algorithm version.** The marker is `ref=hmac:v1:…`;
   `agent_tool_calls` persists `redaction_key_id`, `redaction_version` and an explicit
   `hmac_alg = 'HMAC-SHA256'`, so a future algorithm change is recorded rather than inferred.
3. **Old keys are not retained to preserve historical correlation.** No key history is stored
   anywhere. Rotation replaces the environment value; pre-rotation refs stop matching, and that loss
   is accepted — preserving correlation would require retaining the secrets.
4. **Rotation is audited**, and a silent rotation is detected. A **key check value**,
   `KCV = HMAC(key, "vapt-kcv")` (which reveals nothing about the key), is recorded; a changed KCV
   under an unchanged `REDACTION_KEY_ID` is caught at startup, audited as a misconfiguration, and
   **the agent is disabled until the id is corrected** — otherwise refs would silently stop
   correlating while claiming the same id.
5. **Rotation never changes evidence-integrity hashes.** `content_sha256` and `redacted_sha256` are
   unkeyed SHA-256 computed in `evidence/integrity.py`, which takes no key input. Property test:
   rotate the key, re-verify every integrity hash unchanged.

**Confirmed: the key cannot appear in application logs, configuration dumps, exception messages or
agent prompts**, by four independent means — the `SecretBytes` type (an accidental interpolation
prints `<redacted>`); a structlog processor that scrubs the key's byte value from any log payload by
identity; config-introspection paths (`/system/capabilities` included) emitting the key **id** only;
and registration of the live key value as a **mandatory canary** in the stage-2 redactor, so if it
ever appears in an outbound payload it is redacted *and* an alert is raised. CI asserts the value
appears in no log line, no API response, no prompt and no traceback (invariant **I11**).
