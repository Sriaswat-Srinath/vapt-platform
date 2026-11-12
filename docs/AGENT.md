# AI Investigation Agent (LangGraph)

One bounded graph, `agent/graph.py`, version-pinned as `graph_version` on every run. The agent is a
**reader and explainer**. It has no authority over security boundaries or finding status.

## 1. State

```python
class AgentState(TypedDict):
    run_id: UUID
    asset_id: UUID | None          # pinned at session creation; tools cannot cross it
    question: str
    intent: Literal["explain_finding","summarise_scan","evidence_gap",
                    "impact","remediation","general_qa","out_of_scope"]
    plan: list[PlanStep]           # <= MAX_STEPS
    retrieved: RetrievedContext    # findings, evidence, inventory, risk rows (ids + content)
    notes: list[str]
    citations: list[Citation]
    draft: str | None
    guard: GuardReport | None
    budget: Budget                 # tool_calls_left, tokens_left, seconds_left
    halt_reason: str | None
```

## 2. Graph

```
           ┌──────────────┐
           │ classify     │  deterministic keyword+schema pass, then LLM; out_of_scope → refuse
           └──────┬───────┘
                  ▼
           ┌──────────────┐
           │ plan         │  emits <= MAX_STEPS typed steps, each naming an allowlisted tool
           └──────┬───────┘
                  ▼
     ┌────▶┌──────────────┐    budget ok & gaps remain
     │     │ retrieve     │────────────────┐
     │     └──────┬───────┘                │
     │            ▼                        │
     │     ┌──────────────┐                │
     └─────│ analyse      │◀───────────────┘   loop bounded by budget + step count
           └──────┬───────┘
                  ▼
           ┌──────────────┐
           │ evidence_gap │  compares evidence present vs required-by-validation-rule
           └──────┬───────┘
                  ▼
           ┌──────────────┐
           │ synthesise   │  technical impact, business impact, remediation, confidence caveats
           └──────┬───────┘
                  ▼
           ┌──────────────┐
           │ guard        │  schema + citation + privileged-field + scope checks
           └──────┬───────┘
            pass  │   fail → halted_by_guard (one repair retry, then halt)
                  ▼
           ┌──────────────┐
           │ persist      │  agent_messages, agent_tool_calls, agent_suggestions
           └──────────────┘
```

Budgets (config, enforced in code): `MAX_STEPS=6`, `MAX_TOOL_CALLS=12`, `MAX_TOKENS_PER_RUN`,
`MAX_WALL_SECONDS=120`, one repair retry. Exceeding any ⇒ `budget_exceeded` with the partial answer
returned and clearly labelled partial.

## 3. Tool catalogue (`agent/tools/catalogue.py`) — the complete allowlist

Read-only:
| Tool | Arguments | Returns |
|---|---|---|
| `list_findings` | filters: severity, validation_state, category, job_id, limit≤50 | finding summaries |
| `get_finding` | `finding_id` | finding + validation history + risk row |
| `get_evidence` | `finding_id`, `kind?` | redacted evidence records |
| `get_raw_observation_summary` | `finding_id` | adapter, rule id, hashes, truncated payload |
| `list_attack_surface` | filters | endpoints/params/forms/headers with assessment states |
| `get_endpoint` | `endpoint_id` | detail |
| `get_scan_job` | `job_id` | profile, budgets, phases, stop reason, coverage |
| `get_risk_scoring` | `finding_id` | cvss + priority + inputs + formula version |
| `get_validation_rule` | `rule_id` | rule text, required evidence predicates |
| `get_catalogue_entry` | `catalogue_key` | curated description, CWE, remediation, references |
| `search_evidence` | `query`, `asset_id` | keyword hits over redacted evidence |

Proposal-only (writes a suggestion requiring human acceptance):
| `propose_evidence_gap` | `finding_id`, `missing` | `agent_suggestions` row |
| `propose_rescan` | `finding_id`, `rationale` | suggestion row only — **never** starts a scan |
| `propose_remediation_note` | `finding_id`, `body_md` | suggestion row |
| `propose_triage_opinion` | `finding_id`, `opinion`, `rationale` | suggestion row; explicitly **not** a validation state change |

Every tool: arguments validated by pydantic; `asset_id` forced to the session's asset; row ids must
exist and belong to that asset; `limit` capped; results truncated to a token ceiling; each call
recorded in `agent_tool_calls` with `allowed`/`denial_reason`. There is no tool that accepts a URL,
hostname, shell string, SQL, file path or template.

## 4. Guard (`agent/guard.py`)

1. **Schema**: output must parse into `InvestigationAnswer{summary, technical_impact,
   business_impact, missing_evidence[], remediation[], caveats[], citations[]}`.
2. **Citations**: every claim-bearing sentence must reference an id present in `state.retrieved`.
   Uncited factual claims are either dropped or the run is halted (configurable; default halt).
3. **Privileged fields**: any attempt to emit `validation_state`, `severity`, `confidence`, `cvss*`,
   `epss`, `kev`, `priority_score`, `scope`, `rate_limit` as an assertion of fact is stripped and the
   guard appends "status fields are platform-computed". The model may *discuss* them by citing the
   stored value; it may not state a different one.
4. **Scope**: no host/URL outside the asset's scope may appear in the answer.
5. **Refusal path**: questions requesting exploitation guidance beyond proof-of-presence, scanning of
   anything unregistered, or changes to safety controls are refused by the `classify` node with a
   fixed message.

## 5. LLM provider

`agent/llm/provider.py` is a thin interface (`complete`, `stream`, `structured`). Implementations:
`anthropic` (default, model id from config), `fake` (deterministic, used by every test). Temperature
0 for classification and structured output. Prompts are versioned files under `agent/prompts/` and
hashed into `agent_runs` so an answer is reproducible given the same context. Scanner- and
page-derived text is inserted inside an explicit untrusted-data envelope.

Cost/latency controls: retrieved context is pre-summarised deterministically (counts, tables) rather
than dumping raw bodies; evidence is truncated with explicit markers; per-run token budget enforced.
