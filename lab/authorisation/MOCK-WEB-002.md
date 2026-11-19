# Testing Authorisation — MOCK-WEB-002 (Local Synthetic Lab)

> **STATUS: UNSIGNED DRAFT — NOT YET AN AUTHORISATION.**
> This document carries no authority until an authorised person completes §6 and signs it. Until
> then no `ScopeGrant` may be activated from it. Preflight gate 5 verifies the SHA-256 recorded in
> the grant against this file, so any edit after activation invalidates the grant and blocks
> scanning until it is re-approved.
>
> Authorisation is PER ASSET. Signing the MOCK-WEB-001 document grants nothing here.

## 1. Authorised target — and nothing else

| Field | Value |
|---|---|
| Asset identifier | `MOCK-WEB-002` |
| Application | Supplier Portal — a **static synthetic mock**, not a real portal |
| Nature | **Synthetic. Locally hosted. Disposable. Contains no real data of any kind.** |
| Hostname | `portal.brakes-vapt.test` (Docker network alias, resolvable **only** inside `vapt_lab`) |
| Protocol / port | HTTP / 8080 |
| Network | `vapt_lab`, `172.30.10.0/24`, `internal: true` — no route to any external network |
| Deployment | An nginx container serving three static files from this repository |

## 2. What this document does NOT authorise

Strictly limited to the container described in §1. It confers **no** authority to test, scan,
probe, enumerate or connect to:

- **any Brakes India production, staging, UAT or corporate system, network or domain;**
- any real supplier, customer or third-party portal, however similarly named;
- any public website or SaaS tenant;
- any IP address or hostname not listed in §1;
- the other lab asset `MOCK-WEB-001` — that target has its own document.

The hostname `portal.brakes-vapt.test` is a **local fiction** using the reserved `.test` TLD
(RFC 6761). It exists only as a container network alias and resolves nowhere outside this lab.
**It is not, and must not be read as, a Brakes India asset, domain or subdomain.** There is no
real supplier portal behind it: the container serves three static files.

## 3. Permitted testing

| Permitted | Not permitted |
|---|---|
| Passive assessment (observing responses already requested) | Active/intrusive scanning without a separate approval |
| Spidering within the scope rules | Denial of service, stress or volumetric testing |
| Reading response headers, cookies and served content | Brute force or credential guessing |
| | Persistence, data exfiltration, destructive tests |

## 4. Rate and time limits

As recorded in the `zap-passive` scan profile: 5 requests/second, 5,000 requests total,
30 minutes maximum, `DELETE`/`PUT`/`PATCH` denied.

## 5. Revocation

This authorisation may be revoked at any time by revoking the `ScopeGrant`. Revocation takes
effect at the next preflight evaluation, which every job performs before doing anything.

## 6. Signature (to be completed by hand — do not pre-fill)

| Role | Name | Title | Date | Signature |
|---|---|---|---|---|
| Authorising owner of the lab environment | | | | |
| Operator / tester | | | | |

Once signed, record this file's SHA-256 in the `ScopeGrant` for `MOCK-WEB-002`:

```bash
sha256sum lab/authorisation/MOCK-WEB-002.md
make attest-authorisation DOC=lab/authorisation/MOCK-WEB-002.md
```
