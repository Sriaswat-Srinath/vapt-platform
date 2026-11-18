# ADR-0015 — Gate 2 requires host hygiene as well as containment

**Status:** accepted · **Date:** 2026-11-18 · **Decided by:** the project owner
**Resolves:** the open question in `docs/MVP_PLAN.md` §5

## Context

The lab isolation check produces three verdicts: `isolation_passed` (containment — the scanner
cannot reach the internet or the LAN), `host_hygiene_passed` (no foreign wildcard listener on the
host is reachable from the lab through its gateway) and `access_passed` (the optional workstation
forwarder works).

Gate 2 consumed `isolation_passed` only. On this machine `host_hygiene_passed` is **false**: an
unrelated project (`corelayer-lab-db`) publishes `0.0.0.0:5433`, which lab containers could reach
through the lab gateway (deviation D20). It is not ours to remove.

So the question was whether a scanner that can reach an unrelated service on the operator's own
machine is in scope, given that it never leaves the host.

## Decision

**Both verdicts are required before anything executes.** Gate 2 denies unless containment passed
AND host hygiene passed AND the check is fresh. The verdicts stay **separate**:

* a denial names which half failed, so the operator knows what to fix;
* the recovery path (`make lab-check-containment`) still requires containment only, so restarting
  a dirty ZAP is not blocked by someone else's database;
* `host_hygiene_passed = null` — a check reported before hygiene existed — is a **denial**, not a
  pass. An unknown is not a yes.

The gate is not weakened to make preflight pass. On this machine, live execution is therefore
denied at gate 2 until the listener is resolved, in addition to the standing denials at gate 1
(scanner execution disabled) and gate 5 (unsigned authorisation).

## The investigation, and what it measured

The question "can the lab be isolated from the unrelated service?" was answered by measuring
rather than reasoning. From a container on `vapt_lab`:

| Destination | Result |
|---|---|
| host gateway `172.30.10.1:5433` (the foreign listener) | **TIMEOUT** — silently dropped |
| host gateway `172.30.10.1:22` | ECONNREFUSED — proves the host is reachable at L3 |
| `1.1.1.1:443` | ENETUNREACH — no route |
| `172.30.10.20:3000` (the registered target) | REACHABLE |

So the listener is **not presently reachable** from the lab: the published port DNATs to a
container on a different Docker network, and the return path is dropped by inter-network
isolation.

That measurement does **not** change the verdict, and `host_hygiene_passed` still fails. Two
reasons. First, it is a property of today's firewall and Docker rules, not a control we own: any
change to either could make it reachable without anything in this repository changing. Second, a
check that passed because a drop happened to be in place would be measuring luck.

The measurement is recorded instead, as new probes `PUB-2R:<port>`, so the owner decides with
evidence. These probes do not move any verdict.

## Options for resolving the listener (none applied here)

1. **Bind it to loopback.** `127.0.0.1:5433` instead of `0.0.0.0:5433` in the other project's
   compose file. Cleanest, and belongs to that project's owner.
2. **A host firewall rule** dropping traffic from `172.30.10.0/24` to the host's `5433`. This is a
   change to the machine's security configuration and was deliberately **not** made by this
   platform or by automation.
3. **Move the lab off a bridge network** (a dedicated VM or netns). Correct long-term, out of
   scope now.

Another project's service was not removed, stopped or modified.

## Consequences

* `POLICY_VERSION` becomes `1.1.0`: a gate change is a policy change, and every stored decision
  records which policy produced it.
* `report_isolation.sh` already reported both verdicts, so no ingestion change was needed; a check
  reported by an older client (no hygiene field) now denies rather than passing silently.
* Live execution on this machine stays blocked until the listener is resolved by its owner — which
  is the intended behaviour, not a defect.
