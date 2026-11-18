# ADR-0013 — The vulnerability taxonomy is first-class data, including what we cannot detect

**Status:** accepted · **Date:** 2026-11-18 · **Supersedes:** the free-text `category` field

## Context

`category` was a free string on findings, derived from the ZAP evidence class. Discovery used a
separate vocabulary of "concerns". A category the platform could not detect existed nowhere, so a
report's silence about SSRF was indistinguishable from "no SSRF found", and a surface flagged as
an authentication entry point could never be counted toward the authentication category.

The owner specified twelve Tier-1 categories with priorities and eight Tier-2 categories. A
taxonomy that only contained what we had already implemented would have made that specification
unmeasurable.

## Decision

1. The taxonomy is a seeded table (`vuln_taxonomy`) generated from `app/taxonomy.py`, containing
   **every** category at its owner-assigned tier and priority, whether or not this build can
   detect it.
2. Discovery concerns and finding categories are the same keys. There is one vocabulary.
3. Each category declares an `assertability` — `passive`, `active` or `manual` — describing what
   evidence could *ever* confirm it. This is a property of the category, not of our progress.
4. Coverage (`detection`) is **computed**, never stored: counted at query time from catalogue
   entries, the rule packs that can decide their evidence classes, flagged surfaces and stored
   findings.
5. The seed **fails** if a catalogue entry names a category the taxonomy does not define.
6. Intrusiveness of a proposed test follows the category's assertability, not the caller's
   preference: an `active` category can never be proposed under a passive profile.

## Consequences

* Reports carry a coverage section listing the zeroes, and a derived limitation naming the
  categories that were not assessable at all. A reader cannot mistake absence for a clean result.
* Re-filing a category (HSTS moved to cryptographic failures) is a migration, applied to stored
  findings as well as the catalogue, so a coverage query over history agrees with one over new
  scans.
* Re-filing a legacy discovery concern also re-files the **safety claim** attached to it: rows
  mapped from `input_validation` to `injection` had their `requires_intrusive` recomputed, because
  a row that said "assessable passively" must not survive under a category that is not.
* A category with priority `critical` and no detection capability is now the most visible row in
  the product rather than an absence. That is uncomfortable and correct.

## Rejected alternatives

**Only taxonomise what we detect.** It would have made the table agree with the code at the cost
of making the gap invisible — the exact failure this platform exists to avoid.

**A foreign key from catalogue to taxonomy.** Rejected so a taxonomy edit can never delete a
catalogue entry by cascade. The coverage query reports an entry that does not resolve instead.
