# Detection evaluation

Dataset 1.0.0 · 19 cases · asset MOCK-WEB-001 · 2026-11-18T19:38:19.689162+00:00

> **What this measures.** Whether the pipeline reaches the correct verdict for constructed evidence whose ground truth is known by construction. It does **not** establish real-world detection accuracy: every case is a hand-authored alert over a hand-authored response. A perfect score means the engine is self-consistent.

| Verdict | Count |
|---|---|
| OK | 3 |
| TN | 5 |
| TP | 11 |

| Case | Category | Scenario | Ground truth | Expected | Actual | Verdict |
|---|---|---|---|---|---|---|
| EV-01 | security_misconfiguration | CSP header absent across every stored HTML response, coverage complete | vulnerable | confirmed | confirmed | **TP** |
| EV-02 | security_misconfiguration | Scanner claims X-Content-Type-Options missing on a response that SETS it | not_vulnerable | false_positive | false_positive | **TN** |
| EV-03 | security_misconfiguration | Browser security header claimed missing on a JSON API endpoint | not_applicable | not_applicable | not_applicable | **OK** |
| EV-04 | injection | Payload reflected UNENCODED into an HTML context | vulnerable | confirmed | confirmed | **TP** |
| EV-05 | injection | Payload reflected but HTML-ENCODED in the response | not_vulnerable | false_positive | false_positive | **TN** |
| EV-06 | session_management | Set-Cookie carries no HttpOnly attribute | vulnerable | confirmed | confirmed | **TP** |
| EV-07 | session_management | Scanner claims HttpOnly missing on a cookie that HAS it | not_vulnerable | false_positive | false_positive | **TN** |
| EV-08 | session_management | Set-Cookie carries no SameSite attribute | vulnerable | confirmed | confirmed | **TP** |
| EV-09 | cryptographic_failures | Login form posts credentials to a cleartext HTTP action | vulnerable | confirmed | confirmed | **TP** |
| EV-10 | cryptographic_failures | Auth token written to localStorage by a served script | vulnerable | confirmed | confirmed | **TP** |
| EV-11 | cryptographic_failures | HSTS claimed missing on a response that SETS Strict-Transport-Security | not_vulnerable | false_positive | false_positive | **TN** |
| EV-12 | client_side | DOM sink writes a URL parameter into innerHTML, payload reflected unencoded | vulnerable | confirmed | confirmed | **TP** |
| EV-13 | client_side | Third-party script tag served with no integrity attribute | vulnerable | confirmed | confirmed | **TP** |
| EV-14 | information_disclosure | Server version disclosed in a response header on a JSON endpoint | vulnerable | confirmed | confirmed | **TP** |
| EV-15 | information_disclosure | Session identifier present in a URL in the response body | vulnerable | confirmed | confirmed | **TP** |
| EV-16 | information_disclosure | Debug error message claimed, but the string is ABSENT from the stored body | not_vulnerable | false_positive | false_positive | **TN** |
| EV-17 | information_disclosure | Timestamp disclosure whose evidence string IS present | vulnerable | confirmed | confirmed | **TP** |
| EV-18 | broken_access_control | Anti-CSRF token missing on a form | indeterminate_without_active_testing | candidate | candidate | **OK** |
| EV-19 | unmapped_detection | A scanner rule with no catalogue entry | unknown | candidate | candidate | **OK** |

## Reading the verdicts

* **TP/TN** — the engine agreed with the dataset.
* **FP** — the engine confirmed something that is not a vulnerability.
* **FN** — the engine failed to confirm something that is.
* **OK** — a non-binary case (candidate, not applicable) matched.
* **MISSING** — no finding carried that catalogue key: the detection did not reach the pipeline at all.
