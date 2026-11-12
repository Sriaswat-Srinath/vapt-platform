# Architectural Decisions Needed Before Implementation

> **SUPERSEDED 2026-11-12 — retained for history.** All twelve decisions and all seven
> confirmations were resolved by the project owner. The binding record is
> [DECISION_LOG.md](DECISION_LOG.md); the modifications attached to D2, D3, D4, D7, D10 and D11 are
> captured in ADR-0008…ADR-0011. Do not implement from this file.

Each has my recommendation. Say "all defaults" and I will proceed with the recommended column.

| # | Decision | Options | Recommendation | Why it must be decided now |
|---|---|---|---|---|
| D1 | Job queue | Celery+Redis / arq / custom asyncio worker | **Celery+Redis** | Shapes `worker/`, cancellation semantics, compose topology, and the M3 pause/cancel protocol. Celery is boring and well understood; arq is async-native but weaker on revoke. |
| D2 | Auth model for the MVP | single shared admin token / analyst+approver+admin with API tokens / OIDC | **analyst/approver/admin with hashed API tokens** | Dual-control approval for intrusive profiles is a safety control and needs ≥2 distinct identities, which forces this into M2. |
| D3 | LLM egress | api container may reach the provider / fully offline with a local model / no agent until approved | **api-only egress to one pinned provider**; worker stays airgapped | Determines whether `edge` exists at all and whether M8 can be demoed. |
| D4 | ZAP deployment | long-lived daemon with per-job contexts / one container per job | **daemon in the MVP**, revisit in M11 | Affects the adapter, teardown correctness and the isolation story. |
| D5 | Report PDF | WeasyPrint in the api image / HTML+JSON only / headless Chromium | **WeasyPrint**, with HTML+JSON always available | Adds system libs to the image; cheaper to decide before M2 builds the image. |
| D6 | Authenticated scanning of Juice Shop in the MVP | yes / defer to M13 | **defer**; discovery still records auth entry points | Materially changes M4/M5 scope and the credential-handling design. |
| D7 | Active scanning | permanently off in the MVP / off by default but implemented behind dual-control approval | **implemented, off by default, dual-control + approved profile required** | The approval tables and gates differ; retrofitting approvals later is the risky path. |
| D8 | EPSS/KEV | offline dated snapshots imported by an admin / live fetch / omit | **offline snapshots**, nulls when absent | The worker has no egress by design; this keeps that true. |
| D9 | Fingerprint definition | as specified in `SCANNER_INTEGRATION.md` §5 / include parameter values / per-URL only | **as specified** (param names in, values out) | Changing it later requires a data migration of `findings`. |
| D10 | Analyst override of validation state | allowed with mandatory justification, recorded as a human event / not allowed in the MVP | **allowed with justification** | Determines whether `validation_state` is purely engine-owned; affects report wording and audit. |
| D11 | Evidence raw-body storage | local volume blob store / Postgres large objects / S3-compatible | **local volume**, path recorded in the DB | Affects backup, retention and the admin-only raw endpoint. |
| D12 | Frontend data layer | react-query + generated OpenAPI types / hand-written client / RTK Query | **react-query + generated types** | Prevents API drift; shapes M9's test strategy (msw). |

## Additional confirmations I need

1. **Authorisation document.** `scope_grants` requires a `document_ref` + SHA-256 of a written
   authorisation for `MOCK-WEB-001`. For a self-hosted lab this can be a short internal memo
   committed at `lab/authorisation/MOCK-WEB-001.md`. Confirm that is acceptable, or point me at the
   real document.
2. **Port for the mock asset.** Juice Shop defaults to `3000`. Confirm `http` + `3000`, and the host
   port you want it published on for browsing (default `3000`).
3. **Lab subnet** for `allowed_cidrs` (default `172.30.0.0/16` for the `lab` network).
4. **`.test` hostname.** `shop.brakes-vapt.test` will be a Docker network alias, resolvable only
   inside `lab`. Confirm you do not need it resolvable from your workstation (if you do, that needs a
   host `/etc/hosts` entry pointing at `127.0.0.1` plus the published port, and I will document the
   confusion risk).
5. **Approver identity.** Who is the second person for dual control in the lab? If it is only you, I
   will seed two accounts and note the weakened control explicitly in the report's limitations.
6. **LLM provider + model** and where the key comes from (env var, never committed).
7. **git.** This directory is not a git repository. Shall I `git init` and commit the M0 docs before
   M1?

## Already-made decisions worth recording as ADRs at M1

ADR-0001 modular monolith over microservices · ADR-0002 raw observations immutable and separate from
findings · ADR-0003 deterministic validation engine, LLM advisory only · ADR-0004 CVSS stored
separately from the platform priority score · ADR-0005 network-level egress denial as the primary
scope control, application validation as secondary · ADR-0006 resolve-once-and-pin to defeat DNS
rebinding · ADR-0007 agent writes only proposals requiring human acceptance.
