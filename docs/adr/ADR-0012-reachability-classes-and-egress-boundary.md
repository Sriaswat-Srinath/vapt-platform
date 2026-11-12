# ADR-0012: Network reachability classes, host publishing, and the API egress boundary

- Status: Accepted (2026-11-12) — ratifies M1 deviations D19 and D20
- Relates to: ADR-0005, ADR-0008, `NETWORK_ARCHITECTURE.md`

## Context
M1 measured two facts that the design had assumed away:
1. Docker **silently ignores port publishing** for a container attached only to an `internal: true`
   network (binding recorded, never created).
2. `internal: true` **is not host isolation**: the host reaches lab containers directly, and
   containers reach any host service bound on `0.0.0.0` via the lab gateway `172.30.10.1`.
   Container→internet and container→LAN fail with `ENETUNREACH` (no route), which is the actual
   isolation mechanism.

## Decision
1. **Vocabulary.** Security documents distinguish container→internet, container→LAN,
   container→host (via gateway vs via LAN IP), container→container (same vs other network),
   host→container and LAN-peer→container. `internal: true` is described only as
   container→internet and container→LAN isolation — never as "complete isolation".
2. **Host publishing.** Every published port binds `127.0.0.1`. Probe `I14` fails any `0.0.0.0`
   publish of a VAPT container; `I14b` reports host-wide `0.0.0.0` listeners because lab containers
   can reach them via the gateway. The lab gateway IP is never a valid scan target.
3. **Workstation access to the target (D19)** is a host-side, loopback-only, inbound-only TCP
   relay to the one registered target — fixed destination (refuses any other, including the gateway,
   hostnames and anything outside the lab subnet), no proxying, explicit shutdown, never started
   automatically, negative-tested. It grants no container any capability it lacked.
4. **API egress boundary.** The API has no direct route to the internet; outbound traffic exists only
   as `CONNECT` to the single configured LLM provider host on 443 through an allowlisting egress
   proxy that denies everything else and logs into the audit trail. Application-level: no endpoint
   fetches caller-supplied URLs, the LLM client takes no URL from callers, report rendering refuses
   network fetches, agent tools cannot make HTTP requests.
5. **Worker airgap, direct and indirect.** Worker on internal networks only; no proxy variables, no
   provider credentials, no API token; cannot reach the egress proxy or the API (the API binds only
   its edge interface). Verified by tests in M2, not asserted.

## Consequences
+ Claims match measurements; the two silent failure modes are now probed.
+ The LLM integration cannot become a general proxy: destination allowlisting happens below the
  application, in a component that has no notion of prompts.
− One more container (egress proxy) and a dual-network API; the masquerade-off posture must be
  measured on the target host before it is relied upon (M2 risk list).
− Workstation access to the target is an extra operator step, by design.
