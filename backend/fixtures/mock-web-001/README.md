# Synthetic discovery fixtures — MOCK-WEB-001

**Hand-authored, not recorded from the live target.** No request has been made to
Juice Shop: the authorisation document is unsigned, so the platform must not
contact it (CLAUDE.md rules 6 and 7).

These files represent a Juice-Shop-*shaped* application so the extractors,
inventory and candidate-test matrix can be exercised and demonstrated with no
network at all. `source=fixture` discovery runs read these; `source=live` runs
require the full gate chain, including a signed authorisation.

Each `*.json` is one recorded-shaped response: `path`, `status`, `headers`, `body`.
