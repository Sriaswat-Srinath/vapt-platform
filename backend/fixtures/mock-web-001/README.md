# Synthetic discovery fixtures — MOCK-WEB-001

**Hand-authored, not recorded from the live target.** No request has been made to
Juice Shop: the authorisation document is unsigned, so the platform must not
contact it (CLAUDE.md rules 6 and 7).

These files represent a Juice-Shop-*shaped* application so the extractors,
inventory and candidate-test matrix can be exercised and demonstrated with no
network at all. `source=fixture` discovery runs read these; `source=live` runs
require the full gate chain, including a signed authorisation.

Each `*.json` is one recorded-shaped response: `path`, `status`, `headers`, `body`.

`redirect.json` and `profile.json` were added with the taxonomy work so the
matrix can be exercised across all twelve Tier-1 concerns: they carry a
URL-valued parameter (SSRF surface), an object reference and a commercial
quantity (access control, business logic), a file input (file upload), and a
`Set-Cookie` with no `HttpOnly`/`SameSite` (session management). The cookie
value is the literal string `SYNTHETIC-FIXTURE-VALUE` — nothing here was
observed from a real application.
