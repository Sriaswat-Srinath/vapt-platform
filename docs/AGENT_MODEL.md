# The AI analyst: model, transport and how to change either

## The model

**`claude-haiku-4-5`**, chosen by the owner. The task suits it: each request is
400–1,200 tokens, the answer is short structured JSON, and the platform validates
everything it returns, so nothing rests on the model being careful.

Two things about Haiku 4.5 specifically, both enforced in `agent/client.py`:

* **`output_config.effort` is an error on this model.** It is never sent. The effort
  parameter belongs to the Opus/Sonnet generations.
* **Thinking takes an explicit budget** (`{"type": "enabled", "budget_tokens": N}`),
  not the adaptive form. Off by default (`LLM_THINKING_BUDGET_TOKENS=0`); set ≥1024 to enable.

Cost at the measured 10,213 in / 1,528 out per full run: about **1.8 cents**.

## Why the prompts are small

The first implementation sent the whole world in one call — taxonomy, coverage table,
every finding, the tool catalogue — about **6,900 tokens**, and asked six questions at
once. Version 2 asks each question separately with only what that question needs:

| Prompt | ~tokens |
|---|---|
| `explain_finding` | 460 |
| `suggest_remediation` | ~500 |
| `map_unmapped_detection` | 1,110 (carries the Tier-1 taxonomy) |
| `summarise_coverage_gap`, `prioritise_candidate_tests` | 300–800 |

A model asked one question answers it better than a model asked six, a smaller payload
is less to leak as well as less to pay for, and **this is what makes a small local model
a realistic option** if you ever want zero egress.

## The transport

Official `anthropic` SDK (pinned `1.17.0`) → CONNECT-only egress proxy → TLS → provider.
The api container has no default route, so there is no path that bypasses the proxy.

The local stand-in **serves TLS** (`make standin-tls`) precisely so the test path is the
real path: CONNECT, then TLS, then the Messages API, through the SDK. Plain HTTP through
the proxy is refused — `NET-J4a` asserts it — so a plaintext stand-in would have forced a
different, weaker code path in tests than in production.

The stand-in also still answers a bare `PING` with `PONG` on the same port, by peeking at
the first byte (a TLS ClientHello starts with `0x16`), which keeps the frozen M1.5 probe
`NET-J1b` meaningful.

## Pointing it at a real provider

Four deliberate settings, none of them defaulted:

```bash
ANTHROPIC_API_KEY=sk-ant-...          # never logged, never in a payload
LLM_BASE_URL=                          # empty = api.anthropic.com
LLM_CA_BUNDLE=                         # empty = system trust store
EGRESS_ALLOWLIST=api.anthropic.com:443 # a change to a SECURITY BOUNDARY
LLM_ENABLED=true
```

The allowlist line is the one that matters. `NET-K2` asserts the proxy allowlist contains
**only the destination the api is configured to use**, `NET-K5` asserts the api is pointed
at something the proxy would permit, `NET-K3` asserts no tunnel ever went anywhere else,
and `NET-K2:posture` records in plain words which posture is in force. Changing the
allowlist does not weaken those probes — it changes what they compare against.

`NET-C:api-key-matches-posture` fails if a provider key is present while the agent is
disabled: a credential lying around for no reason.

## Changing the model

Set `LLM_MODEL`. Then **measure it** rather than assuming:

```bash
make agent-eval        # scores whatever the agent is pointed at
make prove-agent-eval  # proves the scorer can detect a bad model
```

`scripts/agent_eval.py` scores four things, all from the platform's own validator:

| Metric | What it catches |
|---|---|
| `malformed_json` | prose instead of JSON |
| `schema_violations` | unknown tool, extra field, invented taxonomy key |
| `uncited_or_invented_citation` | a claim citing a handle that was never supplied |
| `ungrounded_proposals` | paths, headers and parameters that appear nowhere in the evidence |

**`ungrounded` is a crude lexical check** and is labelled as such everywhere it appears. It
catches the hallucination that matters most in a security report — a confident reference to
something that does not exist — and says nothing about whether the reasoning is good.

### It is proven to fail

`make prove-agent-eval` runs the harness against a stand-in configured to misbehave, one
failure mode per question type:

```
--- with a deliberately bad model:        --- with the well-behaved stand-in:
  malformed_json:               1           malformed_json:               0
  schema_violations:            1           schema_violations:            0
  uncited_or_invented_citation: 6           uncited_or_invented_citation: 0
  ungrounded_proposals:         5           ungrounded_proposals:         0
```

A scorer that has never been shown to fail is not evidence of anything.

## If you want zero egress instead

A local model removes the allowlist decision entirely. With the per-tool prompts, a 7–14B
instruct model is a realistic candidate — but use **constrained decoding** (Outlines,
llama.cpp GBNF, vLLM guided JSON) against `client.RESPONSE_SCHEMA`. That makes malformed
JSON and out-of-enum keys structurally impossible, which is the half of the problem a small
model is worst at. It does **not** fix groundedness, which is what `agent_eval.py` measures.
