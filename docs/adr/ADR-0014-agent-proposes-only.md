# ADR-0014 — The agent proposes, over opaque handles, behind a refusing boundary

**Status:** accepted · **Date:** 2026-11-18 · **Implements:** I5, I11 · **Extends:** ADR-0010

## Context

Phase 6 adds the one component that talks to something outside the platform. Two risks, in
opposite directions: what we send could leak, and what comes back could act.

## Decision

**Outbound — a boundary that refuses rather than trusts.** `agent/boundary.py` re-runs redaction
on every string on the way out and refuses the request if that second pass removes anything
(I5), if a bare 32+ character digest appears (I11), or if deployment-identifying material is
present. Stage 1 redacting on write is not enough: a bug there must stop the request, not be
carried over the boundary by a component that trusted it.

This required making redaction **idempotent** — a second pass over already-redacted text now
removes nothing. Without that property the check could not have been "removes anything" and would
have had to be weakened to stay usable.

**Opaque handles, not identifiers.** The model receives `f1`, `f2`, … and never a platform
identifier. A UUID is deployment-identifying material the boundary is right to refuse, and a model
cannot cite a finding it was not given when the only citable tokens are the ones in the map.
Handles become real ids only after the proposal has been validated.

**Inbound — a fixed catalogue, validated totally.** Model output is parsed into proposals drawn
from six allowlisted tools. A proposal naming anything else — including the named forbidden
intents (`set_validation_state`, `set_cvss`, `start_assessment`, `run_command`, …) — is rejected
**and stored as a rejection**, because a silent drop would hide the behaviour most worth watching.
Unexpected fields are rejected rather than ignored. Every claim about a finding must cite it.

**Accepting a proposal changes nothing.** `on_accept` is `"nothing"` for every tool in the
catalogue. Agreement is recorded as a human decision; if the analyst wants a classification
applied, they do it through the analyst-classification endpoint, which is a separate audited
action with a human actor. The audit trail can therefore never show a model as the author of a
classification.

**Transport.** CONNECT-only through the egress proxy to one allowlisted host. The api has no
default route, so there is no path that bypasses it. The worker — the only component that can
reach the target — is on no egress network and never calls this module.

**Off by default.** `LLM_ENABLED=false`. A disabled run is still recorded, with its boundary
report, because a run that never left the building is exactly the one worth being able to prove.

## Consequences

* The agent cannot widen scope, confirm a finding, change a score or start a scan. Those remain
  L2 decisions in deterministic Python (CLAUDE.md rule 13).
* Scanner-controlled text reaches the model. It is data: a payload instructing the model to return
  `enable_scanner` produces a stored rejection, not an action.
* The stand-in used in tests deliberately returns one forbidden proposal, so a test suite that
  only ever saw well-behaved model output cannot pass by accident.
