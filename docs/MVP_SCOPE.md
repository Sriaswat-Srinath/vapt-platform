# MVP Scope (adopted 2026-11-12)

**Build the smallest complete product, not the largest incomplete platform.**

Defining demonstration: *an analyst enters a registered mock website; the platform discovers its
attack surface, determines which tests are relevant, executes them within the approved scope,
validates the results and produces an evidence-backed VAPT report.*

Single asset (Juice Shop) · single scanner (ZAP) · human-supervised · one bounded agent.

## 1. Build / defer

| Build | Defer (schema may exist; no implementation) |
|---|---|
| React dashboard (6 screens) · FastAPI · PostgreSQL/Alembic · Redis · assets · scope · auth + roles · audit chain · isolation verification · ZAP · minimal LangGraph · minimal LLM (explanations + test-selection proposals) · evidence collection · deterministic validation · CVSS · HTML+PDF reports | Nuclei · custom priority score formula · EPSS/KEV · multi-agent · vector DB · Kubernetes · authenticated scanning · multiple targets · IoT/OT · retention purge runs · restoration flow · autonomous exploitation · browser automation · multi-tenancy · threat-intel · ML detection |

## 2. Three layers (unchanged from the approved architecture)
**L1 Execution** — ZAP runs tests. **L2 Deterministic backend** — scope, gates, evidence, validation,
CVSS, policy. **L3 AI investigation** — proposes permitted tests, finds evidence gaps, explains,
recommends. *The agent is never authoritative for whether a vulnerability exists* (ADR-0003, 0007).

## 3. Reconciliation with binding decisions

| Recommendation | Binding decision | Resolution |
|---|---|---|
| Defer custom risk score | ADR-0004 keeps CVSS and priority **separate** | Keep the `risk_scores` columns; **do not implement the priority formula**; UI/report show CVSS only, labelled; `priority_score` NULL |
| Defer EPSS/KEV | D8: missing intel ⇒ NULL, never estimated | Consistent; columns NULL |
| Agent proposes tests | ADR-0007: agent proposes, humans/gates decide | Proposals are `agent_suggestions(kind=test_proposal)`; a **human accepts**, then the full preflight chain decides. The agent never selects a profile, never starts a job |
| "Automatically select relevant tests" | same | **Deterministic surface→candidate-test mapping is L2 code** (`discovery/classify.py` + a static matrix); the agent *ranks and explains* within the permitted set. Selection is reproducible without the LLM |
| Defer retention purge | ADR-0011 R3 defines it before implementation | Defined; `RETENTION_ENABLED=false`; blob store, references and pinning schema **are** built (M5) because evidence integrity depends on them |
| Minimal LLM | ADR-0010 redaction boundary | Boundary is not minimisable: `RedactedText` type gate, two-stage redaction and the egress proxy are built in M6 **before** the first provider call |
| **"Execute injection tests" in the defining demo** | **ADR-0009 / D7: active or intrusive scanning requires two independent attested humans; otherwise disabled** | **CONFLICT — see §4** |

## 4. The conflict you must rule on: active tests in the demonstration

ZAP active-scan rules (injection, XSS, etc.) *send payloads* — they are intrusive by definition and are
gated by `ACTIVE_SCAN_ENABLED` **and** `DUAL_CONTROL_AVAILABLE` (two attested, distinct, active human
identities) **and** an approved intrusive profile **and** a signed authorisation. In a single-operator
environment that gate denies, by design, with no override.

Therefore the demonstration as written ("search endpoint → injection testing → execute") cannot
execute the injection test unless a second human identity exists. Options:

| Option | What the demo shows | Changes required |
|---|---|---|
| **A. Two humans** | the full loop including active injection tests under genuine dual control | a second person registers and is attested; `DUAL_CONTROL_AVAILABLE=true` becomes honourable; nothing else changes |
| **B. Passive-only execution, active proposed-and-denied** | discovery → classification → agent proposes injection test → gate **denies with the ordered reasons** (dual control unavailable) → passive/baseline tests execute → validation → investigation → report that states the limitation | none; this is what the current design produces, and the denial itself is a demonstrable safety behaviour |
| C. Relax the gate for the mock lab | — | **refused**; it would weaken a ratified safety control (ADR-0009 §6: no configuration enables intrusive scanning while dual control is unavailable) |

My recommendation: **plan for B as the guaranteed demo and A as the full demo if a second human is
available**. The code path is identical; only the identity precondition differs.

## 5. Adaptive test selection — deterministic core, agentic ranking
```
discovery inventory ──▶ classify.py (static surface→concern matrix, versioned)
                    ──▶ candidate tests ∩ grant.allowed_profiles ∩ enabled capabilities
                    ──▶ agent ranks + explains (proposal rows, cited to inventory ids)
                    ──▶ analyst accepts/rejects ──▶ preflight gates 1–13 ──▶ job
```
Surface→concern matrix (initial): login form → authentication weaknesses; search/query parameter →
injection; user API → broken access control; product API → data exposure; registration form → input
validation; file upload → file handling. Candidates, never findings.

## 6. What the MVP can and cannot claim
It demonstrates an **agentic web-security assessment workflow on a synthetic target**. It does not
substantiate enterprise-grade autonomous VAPT, production readiness, authenticated testing or broad
coverage; those need separate validation. Every report states this.
