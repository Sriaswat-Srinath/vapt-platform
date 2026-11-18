# The vulnerability taxonomy

`backend/app/taxonomy.py` is the source; `vuln_taxonomy` is the seeded table; everything else
(catalogue, discovery matrix, findings, coverage, reports, the agent) references its keys.

## Why it is data and not a label

Before this, `category` was a free string derived from the ZAP evidence class, and discovery spoke
a *different* vocabulary (`authentication_weaknesses`, `data_exposure`, `file_handling`). Two
consequences, both bad:

1. A flagged surface could never be counted against the category it belonged to.
2. A category the platform cannot detect simply did not exist anywhere, so a report's silence
   about it was indistinguishable from a clean result.

The taxonomy fixes both. Every category has a row whether or not this build can detect it, which
is what makes `GET /assets/{id}/coverage` able to return the **zeroes**.

## Three separate questions, deliberately not merged

| Field | Question it answers | Who decides |
|---|---|---|
| `tier`, `priority` | What matters, and in what order | the owner |
| `assertability` | What evidence could *ever* confirm it | the nature of the category |
| `detection` (computed) | What THIS BUILD can assert today | counted from catalogue + rule packs |

`assertability` is `passive` (confirmable from observed traffic), `active` (needs crafted
requests — intrusive, dual control) or `manual` (needs human judgement; no automated
confirmation). It is a property of the category, not of our progress: no build will ever confirm
a business-logic flaw with a scanner.

## Tier 1 — the MVP set

| # | Category | Priority | Assertability | OWASP 2021 |
|---|---|---|---|---|
| 1 | Broken Access Control | critical | active | A01 |
| 2 | Authentication | critical | active | A07 |
| 3 | Session Management | critical | passive | A07 |
| 4 | Injection | critical | active | A03 |
| 5 | Security Misconfiguration | critical | passive | A05 |
| 6 | Cryptographic Failures | high | passive | A02 |
| 7 | Information Disclosure | high | passive | A01 |
| 8 | File Upload | high | active | A04 |
| 9 | API Security | high | active | A04 |
| 10 | Business Logic | high | **manual** | — |
| 11 | SSRF | high | active | A10 |
| 12 | Client-Side | high | passive | A03 |

## Tier 2 — after the first demonstration

Software supply chain · Infrastructure configuration · Denial of service · HTTP protocol ·
Error handling · Logging and monitoring · Identity management · Privacy.

Catalogued so they can be reported as **out of scope** rather than silently omitted. Denial of
service is listed and will never be executed: it is excluded by project constraint.

## Detection states

| State | Meaning |
|---|---|
| `detects` | a catalogue entry **and** a rule pack that can reach a verdict from stored evidence |
| `partial` | some entries are decidable, but the category as a whole needs crafted requests or judgement |
| `surface_only` | discovery flags the surface; confirmation needs evidence this build does not collect |
| `catalogued` | an entry exists so a detection can be mapped and scored, but nothing produces one |
| `none` | no catalogue entry at all — this build cannot report the category in any form |

A clean result in anything but `detects` is **not** a clean bill of health, and the report says so
in those words.

## Current coverage (catalogue 1.1.0, rules 1.1.0, matrix 2.0.0)

26 catalogue entries across 11 of the 12 Tier-1 categories. Business logic has none, by design.

| Category | Catalogue | Rule packs | Detection |
|---|---|---|---|
| Security Misconfiguration | 5 | missing_header, header_value | detects |
| Session Management | 4 | **cookie_attribute (new)** | detects |
| Information Disclosure | 4 | pattern_in_body, header_value | detects |
| Cryptographic Failures | 3 | missing_header, pattern_in_body | detects |
| Injection | 2 | reflected_input | partial |
| Client-Side | 2 | reflected_input, pattern_in_body | detects |
| Broken Access Control | 2 | — | surface only |
| Authentication, API Security, File Upload, SSRF | 1 each | — | surface only |
| Business Logic | 0 | — | none |

## Adding a category's detection

1. Add catalogue entries in `backend/app/catalogue.py` with the taxonomy key as `category`.
2. Map the scanner rules that report it in `normalization/zap_mapping.py`, choosing an evidence
   class.
3. If no existing rule pack can decide that evidence class, add one in `validation/engine.py` —
   and only claim `confirmed` where the stored evidence genuinely supports it.
4. Extend `discovery/classify.py` if a new surface shape should be flagged.
5. Bump the relevant version constant. The coverage query picks the change up with no further
   work, and the report's limitations section re-derives itself.

The seed refuses to run if a catalogue entry names a category the taxonomy does not define.
