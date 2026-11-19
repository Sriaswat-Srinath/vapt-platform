# M9 — findings vs independently known weaknesses

Dataset 1.0.0 · mode **fixture** · 11/11 expectations matched

> **This compares FIXTURE output against real-world expectations. It says nothing about live detection. Re-run against a live job.**

> A missed expectation is a QUESTION, not a verdict: the crawl may not have reached the page, the budget may have been exhausted, or the deployment may differ from the published default.

## Expected and found

| ID | Category | Expectation | Confidence | Findings | States |
|---|---|---|---|---|---|
| GT-01 | security_misconfiguration | No Content-Security-Policy on HTML responses | high | 3 | confirmed, not_applicable |
| GT-02 | security_misconfiguration | No X-Content-Type-Options: nosniff | high | 2 | confirmed, false_positive |
| GT-03 | security_misconfiguration | No anti-clickjacking header (X-Frame-Options / frame-ancestors) | medium | 1 | confirmed |
| GT-04 | cryptographic_failures | No Strict-Transport-Security | high | 1 | false_positive |
| GT-05 | cryptographic_failures | Credentials submitted over cleartext HTTP | high | 1 | confirmed |
| GT-06 | cryptographic_failures | Authentication token kept in browser storage | medium | 1 | confirmed |
| GT-07 | information_disclosure | Server/framework version disclosed (Express) | medium | 1 | confirmed |
| GT-08 | information_disclosure | Timestamps disclosed in API responses | medium | 2 | confirmed, false_positive |
| GT-09 | session_management | Cookie set without one or more of HttpOnly / SameSite | medium | 2 | confirmed, false_positive |
| GT-10 | broken_access_control | Forms served without an anti-CSRF token | medium | 1 | candidate |
| GT-11 | client_side | Third-party script loaded without Subresource Integrity | low | 1 | confirmed |

## Expected and NOT found

None.

## Found but not expected

| Catalogue key | Count | States | Examples |
|---|---|---|---|
| `information-disclosure-debug-errors` | 1 | false_positive | Information Disclosure - Debug Error Messages |
| `session-id-in-url` | 1 | confirmed | Session ID in URL Rewrite |
| `dom-xss` | 1 | confirmed | Cross Site Scripting (DOM Based) |
| `cookie-missing-samesite` | 1 | confirmed | Cookie without SameSite Attribute |
| `reflected-xss` | 2 | confirmed, false_positive | Cross Site Scripting (Reflected) |
| `cache-control-directives` | 1 | confirmed | Re-examine Cache-control Directives |

## Out of passive reach by construction

* SQL injection on the login form — requires payloads (active)
* Reflected or stored XSS — requires payloads (active)
* IDOR on basket or user objects — requires two accounts and crafted requests
* Broken authentication / weak passwords — credential guessing is out of scope entirely
* Business logic flaws (coupon, quantity, price) — no scanner confirms these
