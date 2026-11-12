# ADR-0006: Resolve once, pin the IP, send an explicit Host header

- Status: Accepted (2026-11-12)

## Context
A hostname validated at preflight can resolve differently at request time (DNS rebinding,
split-horizon, TTL expiry, a changed Docker alias). Validating the name is not validating the
destination.

## Decision
Preflight gate 8 resolves the asset hostname once via the lab resolver and requires **every**
returned address to fall inside `scope_grants.allowed_cidrs`. Zero addresses, mixed in-scope and
out-of-scope results, or a CNAME leaving the allowed host set ⇒ deny. The resolved addresses are
pinned into the `scan_jobs` / `discovery_runs` row; all subsequent connections go to a pinned IP with
an explicit `Host` header, and redirects are re-validated against the same pinned set. Membership in
the lab subnet is **not** sufficient authorisation on its own: the exact registered host and port
allowlist is enforced in addition (gates 9–10).

## Consequences
+ The rebinding window between validation and request is closed.
+ Resolution history is observable (`asset_resolutions`), so a changed alias is visible.
− Virtual-host-dependent targets must be correct about `Host`; this is explicit in the adapter spec.
− ZAP performs its own resolution internally, so its context include/exclude regexes plus post-hoc
  rejection of out-of-scope finding URLs are required as compensating controls.
