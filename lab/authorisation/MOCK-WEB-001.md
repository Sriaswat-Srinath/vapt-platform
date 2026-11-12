# Testing Authorisation — MOCK-WEB-001 (Local Synthetic Lab)

> **STATUS: UNSIGNED DRAFT — NOT YET AN AUTHORISATION.**
> This document carries no authority until an authorised person completes §7 and signs it. Until
> then no `ScopeGrant` may be activated from it. Preflight gate 5 verifies the SHA-256 recorded in
> the grant against this file, so any edit after activation invalidates the grant and blocks scanning
> until it is re-approved.

## 1. Authorised target — and nothing else

| Field | Value |
|---|---|
| Asset identifier | `MOCK-WEB-001` |
| Application | OWASP Juice Shop — a deliberately vulnerable, open-source **training application** |
| Nature | **Synthetic. Locally hosted. Disposable. Contains no real data of any kind.** |
| Hostname | `shop.brakes-vapt.test` (Docker network alias, resolvable **only** inside the `vapt_lab` container network) |
| Protocol / port | HTTP / 3000 |
| Workstation access | `http://127.0.0.1:3000` (loopback-bound publish only) |
| Network | `vapt_lab`, `172.30.10.0/24`, `internal: true` — no route to any external network |
| Deployment | Container on the operator's own workstation, from a digest-pinned public image |

## 2. What this document does NOT authorise

This authorisation is **strictly limited to the synthetic Juice Shop container described in §1**. It
confers **no** authority, express or implied, to test, scan, probe, enumerate, connect to or
otherwise interact with:

- **any Brakes India production system, application, network, device, domain or IP address;**
- **any Brakes India staging, test, UAT, pre-production or internal corporate system;**
- any Brakes India corporate network, VPN, directory service, email or endpoint;
- any public website, third-party service, SaaS tenant, customer or supplier system;
- any IP address, hostname or domain not listed in §1;
- any IoT, OT, ICS, firmware, mobile or network-infrastructure target;
- any other container or host inside `172.30.10.0/24` that is not the registered asset in §1.

The hostname `shop.brakes-vapt.test` is a **local fiction**. The `brakes-vapt.test` label uses the
reserved `.test` TLD (RFC 6761), exists only as a container network alias, and resolves nowhere
outside this lab. **It is not, and must not be read as, a Brakes India asset, domain or subdomain.**

Any finding produced under this authorisation describes the synthetic Juice Shop application only. It
says nothing about the security posture of any real Brakes India system, and must not be presented as
if it did.

## 3. Permitted activity

- Unauthenticated attack-surface discovery: crawling, endpoint/parameter/form/header enumeration.
- OWASP ZAP **passive** scanning and the configured local baseline profile.
- Evidence collection (request/response capture) and deterministic finding validation.
- Rate-limited, concurrency-limited, request-capped and time-capped requests per the approved scan
  profiles.

## 4. Prohibited activity (regardless of any configuration)

Denial-of-service or stress testing · destructive or state-mutating exploitation · brute-force or
credential-stuffing attacks · persistence or backdoor installation · credential theft · data
exfiltration · malware · detection evasion · exploitation beyond proof-of-presence · any form of
social engineering · scanning outside §1.

**Active and intrusive scanning is not authorised by this document.** It requires, additionally, an
approved intrusive profile and **two independent human approvals**. Where only one human operates
this environment, genuine dual control does not exist and intrusive profiles remain disabled — see
`docs/adr/ADR-0009-dual-control-single-operator.md`. Approvals recorded without two independent
humans are labelled as simulated and are **not** independent human approval.

## 5. Validity

| Field | Value |
|---|---|
| Valid from | _to be completed on signature_ |
| Valid until | _to be completed on signature — a bounded window, not open-ended_ |
| Revocation | Immediate on request by the signatory; revocation blocks new runs and cancels in-flight jobs at the next phase boundary |

## 6. Operator obligations

1. Keep the target on the isolated, non-routable `vapt_lab` network; publish only on loopback.
2. Do not add a workstation hosts-file entry for `shop.brakes-vapt.test`.
3. Run the lab isolation check before scanning; if egress is reachable, scanning stays disabled.
4. Treat all evidence as synthetic and keep it out of version control.
5. Stop and escalate if any request appears to leave the lab network.

## 7. Signature (to be completed by hand — do not pre-fill)

| Role | Name | Title | Date | Signature |
|---|---|---|---|---|
| Authorising owner of the lab environment | | | | |
| Operator / tester | | | | |

Once signed, record this file's SHA-256 in the `ScopeGrant` for `MOCK-WEB-001`:

```bash
sha256sum lab/authorisation/MOCK-WEB-001.md
```
