# Taxonomy, coverage, and the advisory agent (phase 6)

Baseline `79b6dde`. Two pieces of work, delivered together because the second depends on the
first: the vulnerability taxonomy became **first-class data**, and the AI analyst was built on
top of it — proposing only, inside a boundary that refuses rather than trusts.

**Still no live scan.** Scanner execution disabled, authorisation document unsigned, every
assessment in fixture mode. The agent's only destination is a local test stand-in.

## 1. The taxonomy

Twelve Tier-1 categories at the owner's priorities and eight Tier-2 categories are now rows in
`vuln_taxonomy`, seeded from `app/taxonomy.py`. Discovery concerns and finding categories are
**the same keys**: before this, discovery spoke `authentication_weaknesses` while findings spoke
`security_misconfiguration`, so a flagged surface could never be counted toward its category.

Each category declares an `assertability` — `passive`, `active` or `manual` — describing what
evidence could *ever* confirm it. That is separate from `detection`, which is computed at query
time from what this build actually has. The distinction is the point: no future build will confirm
a business-logic flaw with a scanner, and saying so is more useful than a roadmap entry.

Full detail: [TAXONOMY.md](TAXONOMY.md) · [ADR-0013](adr/ADR-0013-taxonomy-as-first-class-data.md).

## 2. Catalogue and rule packs, grown category by category

| | Before | After |
|---|---|---|
| Catalogue entries | 12 | **26** |
| Tier-1 categories with entries | 4 | **11 of 12** |
| Evidence classes with a deciding rule pack | 4 | **5** |
| Tier-1 concerns the discovery matrix can emit | 4 (own vocabulary) | **12** |

New catalogue entries cover session management (4), cryptographic failures (3), client-side (2),
information disclosure (+1), API security, broken access control (IDOR), SSRF, file upload and
authentication. Business logic has **none**, deliberately: no scanner confirms it, and the matrix
flags its surface for a human instead.

**A new rule pack that genuinely decides:** `cookie_attribute` (session management). A cookie's
attributes are wholly contained in a response already stored, so the claim is decidable without
sending anything. It reads attribute **names** only — never a cookie value — and discriminates in
both directions on the fixtures: `confirmed` where `HttpOnly`/`SameSite` are genuinely absent,
`false_positive` where the cookie carries them, `not_applicable` for `Secure` over cleartext HTTP
(where the transport itself is the finding). The verdicts survive revalidation, because
revalidation reads the unredacted blob store rather than the redacted display evidence.

**The matrix now emits all twelve Tier-1 concerns.** Parameter names are tokenised across
camelCase, snake_case, kebab-case and dotted paths, so `imageUrl`, `image_url` and
`BasketItem.imageUrl` are treated identically. Intrusiveness follows the category's assertability,
not the caller's preference: an `active` category can never be proposed under a passive profile.

## 3. Coverage — the zeroes are the product

`GET /assets/{id}/coverage` returns every category with its catalogue count, decidable entries,
flagged surfaces, findings by state, and a computed detection state. Against the registered asset:

| Detection | Tier-1 categories |
|---|---|
| `detects` | 5 — session management, security misconfiguration, cryptographic failures, information disclosure, client-side |
| `partial` | 1 — injection |
| `surface_only` | 5 — broken access control, authentication, file upload, API security, SSRF |
| `none` | 1 — business logic |

The dashboard has a **Coverage** screen showing this with the blockers named per row ("active
scanning is disabled; intrusive testing needs two independent approvals"). The report gained a
`coverage` section (template **1.1.0**) and two derived limitations:

> 1 of 12 Tier-1 vulnerability categories were NOT assessable by this build: Business Logic. No
> detection exists for them here, so their absence from this report is not evidence of their
> absence in the target.
>
> 5 further categor(ies) were identified on the attack surface but could not be confirmed: Broken
> Access Control, Authentication, File Upload, API Security, Server-Side Request Forgery.

## 4. The AI analyst (phase 6)

Advisory, off by default, and structurally unable to decide anything.
Detail: [ADR-0014](adr/ADR-0014-agent-proposes-only.md).

| Control | How it is enforced |
|---|---|
| No unredacted evidence leaves (**I5**) | every outbound string is re-redacted; if that pass removes anything, the request is **refused**, not sent |
| No plain secret digest leaves (**I11**) | a bare 32+ char digest refuses on sight; correlation uses keyed HMAC refs |
| No deployment identity leaves | tokens, connection strings and application-plane addresses refuse |
| The model never sees our identifiers | it receives opaque handles `f1…fn`; handles become ids only after validation |
| The model cannot act | six allowlisted tools; anything else — including named forbidden intents — is rejected **and stored** |
| Claims must be cited | a statement about a finding must cite it, and may only cite handles actually sent |
| Accepting changes nothing | `on_accept` is `"nothing"` for every tool; applying a classification is a separate audited human action |
| One route out | CONNECT-only through the egress proxy to one allowlisted host; the api has no default route |
| The worker never calls it | it is on no egress network, and its `LLM_ENABLED` is hard-coded false |

**Measured end to end** against the local stand-in (`make test-agent`): 22 191 bytes sent, 473
fields checked by the boundary with 0 re-redactions and 5 keyed refs surviving, 4 ms round trip,
3 proposals accepted with citations resolved to real findings, and the stand-in's deliberately
forbidden `set_validation_state` proposal **rejected and recorded**. The flag is restored to false
afterwards whatever the result.

## 5. Tests

| Suite | Result |
|---|---|
| `tests/backend` | **228 passed, 4 skipped** (39 new taxonomy, 39 new agent) |
| `backend/tests/invariants` | **23 passed, 1 skipped** — I5 and I11 now implemented, P6 landed |
| `scripts/net_verify.sh` | **115/115**, `net_passed: true` |
| `tests/net` / `tests/lab` | unchanged and green |

New assertions worth naming: every emitted concern is a Tier-1 taxonomy key; the matrix can flag
all twelve; a manual category never suggests a scanner profile; coverage returns every category
including zeroes; a category with no detection capability cannot have findings; each of the twelve
is individually reachable over the API; redaction is idempotent (the property the I5 check rests
on); every forbidden intent is rejected **by name**; a proposal cannot cite a finding it was not
given; the agent cannot invent a taxonomy category; injected instructions in evidence produce a
stored rejection rather than an action; and accepting a proposal leaves the cited finding's
validation, severity, category and fingerprint unchanged.

## 6. Defects found and fixed

| Defect | Consequence | Fix |
|---|---|---|
| **Redaction was not idempotent** — a second pass re-redacted its own markers | every agent payload looked unsafe; the I5 check would have had to be weakened to "equality after normalisation", which is a far weaker property | markers are recognised and left alone in header, query, form and JSON paths; redaction 1.1.0. Verified across six value shapes |
| **A cookie value could masquerade as an attribute** — `Set-Cookie: token=HttpOnly` was read as carrying the flag | a genuine session-management finding would have been reported as a false positive | the first `;` segment is NAME=VALUE and is discarded unread; attributes are matched by name |
| **Re-filing a concern kept its old safety claim** — legacy `input_validation` rows became `injection` but stayed non-intrusive | a candidate claiming injection is testable under a passive profile | the migration recomputes `requires_intrusive` from the taxonomy's assertability for every pre-2.0.0 row |
| **Autogenerated an EMPTY migration** — the image was built before the new models, so alembic compared against stale metadata, and `db-check` then reported "no new operations" | the agent tables would have been missing at runtime with a green check | rebuild before autogenerate; caught because the generated file had no operations in it |
| **`findings.category` disagreed with the catalogue** for re-filed entries | a coverage query over history contradicted one over new scans | the migration updates stored findings from the catalogue |
| Internal UUIDs tripped the outbound boundary | the agent could never run at all | opaque handles, which is the better design anyway |
| `Finding.quarantined` does not exist (it is `quarantined_at`) | the coverage endpoint 500'd | fixed; caught by exercising the endpoint rather than trusting the model name |

## 7. Limitations

1. **Still no live scan**, so every coverage figure describes fixture data.
2. **Seven Tier-1 categories cannot be confirmed by this build** — six need active/intrusive
   testing (disabled, and dual control is unavailable with one operator), one needs human
   judgement. The platform reports this rather than implying coverage.
3. **The agent is a bounded single pass**, not a LangGraph multi-step graph: it has no executable
   tools, so iteration would buy nothing a second analyst request would not. Revisit if tools
   that read more data are ever added.
4. **The stand-in is not a model.** It returns deterministic canned proposals shaped like model
   output. Behaviour against a real provider — refusals, drift, malformed JSON under load — is
   unmeasured, though the parser treats all of it as untrusted input.
5. **Tier 2 is catalogued but unimplemented**, by the owner's sequencing.
6. Evidence is still unencrypted at rest; retention purge (I12) remains due at phase 8.

**Next: phase 8 — hardening (retention purge and I12, rate limiting, the open gate-2 question).**
