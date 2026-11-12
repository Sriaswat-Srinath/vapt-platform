# Agent Redaction Data Flow

Normative for M8. Implements ADR-0010 + R2. One rule governs everything here: **nothing reaches the
LLM that has not been parsed, redacted and typed as `RedactedText`.**

## 1. The boundary

```
   ┌─ vapt_lab (airgapped) ─┐      ┌──────── vapt_core ────────┐   ┌─ vapt_edge ─┐
   │ juiceshop ──▶ zap      │      │ postgres   blob store     │   │             │
   │        │               │      │   │           │           │   │             │
   │        ▼  raw bytes    │      │   │           │           │   │             │
   │   worker (no LLM key,  │─────▶│ evidence   evidence_blobs │   │             │
   │    no egress)          │      │ (redacted)  (unredacted)  │   │             │
   └────────────────────────┘      └───┬───────────────┬───────┘   └──────┬──────┘
         STAGE 1 redaction on write    │               │                  │
         (discovery/ + normalization/) │               │                  │
                                       │               ✗ agent has NO     │
                                       │                 path here        │
                                       ▼                                  │
                           ┌───────────────────────┐                      │
                           │ read-only service     │                      │
                           │ facades (api process) │                      │
                           └───────────┬───────────┘                      │
                                       ▼                                  │
                           ┌───────────────────────┐                      │
                           │ agent/tools/*         │  returns RedactedText│
                           │   every result passes │                      │
                           │   STAGE 2 redaction   │                      │
                           └───────────┬───────────┘                      │
                                       ▼                                  ▼
                           ┌───────────────────────┐          ┌────────────────────┐
                           │ PromptEnvelope        │─────────▶│ one configured LLM │
                           │ [RedactedText]        │          │ provider           │
                           └───────────────────────┘          └────────────────────┘
```

Stage 1 (on write) and stage 2 (on egress) are independent implementations of the same policy. Stage
2 is not a formality: stage 1 may miss a novel format, and stage 2 also covers text that never went
through stage 1 (exception messages, tool errors, computed summaries).

## 2. Type gate

- `RedactedText` lives in `agent/redaction.py`; its constructor is module-private and subclassing is
  blocked. Nothing outside that module can produce one.
- Every tool signature returns `RedactedText` (or a model whose text fields are `RedactedText`).
- `LLMProvider.complete/stream/structured` accept **only** `PromptEnvelope[RedactedText]`. Passing a
  `str` raises at runtime — tested, not assumed.
- Prompt templates interpolate `RedactedText` only; a template rendering a raw object fails CI.
- import-linter forbids `agent/` from importing: blob readers, raw-evidence readers, repositories,
  `sqlalchemy`, `httpx`, `subprocess`, `pathlib.open` wrappers.
- Fail-closed: any redactor exception yields **empty** `RedactedText` plus a tool error (itself
  redacted). There is no path that returns raw text on error.

## 3. Per-call pipeline

```
tool invoked
 └─ pydantic arg validation (ids only; asset_id forced to the session's asset; limits capped)
    └─ read-only facade query
       └─ STAGE 2 redact(value, content_hint)
          ├─ 1. detect container type (json | url | html | multipart | xml | text | exception)
          ├─ 2. parse with resource limits (max depth, max nodes, max bytes, no entity expansion)
          ├─ 3. walk; for each leaf: name match  ∪  value-shape match  ∪  decoded-value match
          ├─ 4. replace with <redacted:kind=…,len=…,ref=hmac:v1:XXXXXXXXXXXX>
          ├─ 5. re-serialise; truncate to budget with <truncated N bytes>
          └─ 6. emit RedactionReport{counts by kind, parser used, truncated, fallback_used}
             └─ parse failure ⇒ redact the WHOLE value, never pass through
    └─ persist agent_tool_calls{allowed, redaction_version, redaction_key_id,
                                redaction_report, result_sha256(of the redacted text)}
    └─ wrap in an untrusted-data envelope and hand to the model
```

## 4. Identifiers

| Identifier | Over what | Purpose | May reach the LLM |
|---|---|---|---|
| `ref=hmac:v1:…` | the secret value, HMAC-keyed | correlation ("same token as before?") | **yes** |
| `evidence.content_sha256` | the unredacted original document | integrity / provenance | **no** |
| `redacted_sha256` | the redacted text | integrity of what was shown | no |
| `agent_tool_calls.result_sha256` | the redacted payload | audit of what crossed | no |
| `payload/request/response_sha256` | raw observation parts | provenance | **no** |

Plain SHA-256 of a secret value is never produced or exposed — that was the R2 defect. Keyed refs are
not invertible without `REDACTION_HMAC_KEY`, which never leaves the api container and is never logged
or audited.

## 5. Untrusted-data envelope

Target-derived text (page content, alert text, evidence) is wrapped:

```
<<UNTRUSTED_EVIDENCE id=evidence:…  source=zap_passive  redaction=v1>>
…redacted content…
<<END_UNTRUSTED_EVIDENCE>>
```

The graph has no node that can act on instructions found inside an envelope: the only actions
available are the allowlisted read tools and the four proposal tools, all argument-validated against
existing ids. Instruction-shaped content is data to be reported, not followed.

## 6. What the agent sees versus what exists

| Field | Analyst in UI | Agent |
|---|---|---|
| redacted evidence text | full | full (re-redacted) |
| unredacted body | `admin` only, `?raw=true`, justification, audited | **never, by any path** |
| secret values | as stored (redacted) | never |
| secret correlation | — | keyed refs |
| raw observation payload | paginated, redacted | summary + excerpt only |
| content hashes | yes | no |

## 7. Test obligations (M8)

The eight structural contexts and their cases in ADR-0010 §9 · canary sweep (seeded secrets must not
appear in any prompt, tool result, error, or persisted agent row) · LLM client rejects `str` ·
`RedactedText` cannot be constructed outside the module · each closed indirect path in ADR-0010 §10 ·
redactor exception ⇒ empty result + tool error · parser resource limits (deep JSON, billion-laughs
XML, huge multipart) ⇒ bounded failure then whole-value redaction · benign base64/high-entropy data
survives unredacted (false-positive direction) · key rotation changes refs and is recorded ·
`LLM_ENABLED=false` ⇒ agent endpoints 412 and no provider call is constructed.
