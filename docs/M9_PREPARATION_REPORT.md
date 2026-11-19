# M9 preparation — what was built, and what now waits on a person

Baseline `e257615`. The answer to "can it analyse a real website?" was **no, by design**, and the
decision was to **stay lab-only and proceed to M9**: the first genuine passive assessment of the
registered Juice Shop target.

No external-target capability was added. No scanner was enabled. The authorisation document is
still an unsigned draft, byte-identical to `83497ce`.

---

## 1. The gap this found, which mattered more than the feature

The authorisation document states, in its own header:

> Preflight gate 5 verifies the SHA-256 recorded in the grant against this file, so any edit after
> activation invalidates the grant and blocks scanning until it is re-approved.

**It did not.** `document_sha256` was recorded by `verify-document` and then **never compared with
anything**. A signed document could have been edited after approval — widening scope, naming a
different target, removing an exclusion — and the gate chain would not have noticed. The document
promised a control that did not exist.

That is the worst possible place for a gap, because every authorised finding rests on "this signed
document authorises exactly this target", and M9 is the first milestone that would have relied on
it.

### What now enforces it

Gate 5 (policy **1.2.0**) additionally requires:

| Condition | Denial |
|---|---|
| the grant records a document digest | "records no document digest, so the authorisation it rests on cannot be verified" |
| a digest has been attested for that document | "no current digest has been attested … run `make attest-authorisation`" |
| the attested digest **equals** the approved one | "the authorisation document has **CHANGED** since it was approved … Re-verify and re-approve it" |
| the attestation is fresh (default 24h) | "the document attestation is N minutes old (limit …)" |

The platform never reads the host filesystem — the operator measures and reports, exactly as for
the lab isolation check. New table `authorisation_attestations`, new admin endpoint, and
`make attest-authorisation`.

### Proved, not asserted

`scripts/prove_authorisation_tamper.sh`, on a scratch copy of the document:

```
BASELINE  gate 5 with the approved digest  -> PASS
TAMPERED  gate 5 after the edit            -> DENY
  reason: the authorisation document has CHANGED since it was approved: the grant
          records b122cf30cdf2… and the attested file is 0f855f112002….
REVERTED  gate 5 with the original digest  -> PASS
```

It signs nothing and activates nothing. 19 tests cover the gate's branches, including that the
real document is still unsigned and that it still promises exactly what the gate now enforces.

---

## 2. M9 readiness, measured

`make m9-readiness` reports every precondition with its live state and **who must act**. It is
read-only by construction, and a test asserts it cannot verify, activate or enable anything.

```
ok lab target running                  vapt_juiceshop health=healthy
ok ZAP container running               vapt_zap status=running
ok containment (gate 2a)               isolation_passed=True
XX host hygiene (gate 2b)              listeners=0.0.0.0:5433
   -> owner of the foreign service: bind it to loopback (ADR-0015)
XX ZAP daemon clean (gate 13)          adapter=disabled (ZAP_ADAPTER_ENABLED=false)
XX authorisation document signed       §7 signature table EMPTY
   -> HUMAN: sign §7 by hand — nothing in this repository may do it
ok document digest attested            attested=b122cf30cdf2… current=b122cf30cdf2…
XX scope grant signed+verified         document_state=unsigned_draft
XX scope grant active                  grant state=draft
XX scanner execution enabled (gate 1)  SCANNER_EXECUTION_ENABLED=False
XX ZAP adapter enabled                 ZAP_ADAPTER_ENABLED=False
ok active scanning OFF (required)      ACTIVE_SCAN_ENABLED=False
XX preflight dry run                   decision=deny policy=1.2.0 denying=4

6/13 ready · 1 needs a person, not this platform
```

---

## 3. For your step 3 — independent review

[M9_SCANNER_REVIEW.md](M9_SCANNER_REVIEW.md) states what would actually run (`zap-passive`: no
active scanner, 5 req/s, 5000 request ceiling, 30-minute limit, `DELETE`/`PUT`/`PATCH` denied,
logout and user-mutation paths excluded), what the scanner can reach (with the probe id behind
each claim), and six things a reviewer should verify **themselves** rather than take from the
document.

It also gives the enabling sequence in order, with who acts at each step. Two steps are
deliberately not automatable: the signature, and activation by a second person. If either is
simulated, the resulting findings are not authorised findings.

---

## 4. For your step 10 — ground truth to compare against

[`m9_ground_truth.json`](../backend/fixtures/evaluation/m9_ground_truth.json) — 12 expectations
drawn from what is **independently known** about Juice Shop and **limited to what passive
observation can see**: missing CSP/nosniff/frame protection, cleartext credentials, HSTS absent,
client-side token storage, version and timestamp disclosure, cookie attributes, absent CSRF tokens,
SRI, and the REST surface.

Five classes are listed as explicitly **out of passive reach**: SQL injection, XSS, IDOR, broken
authentication and business logic. A scan that does not report them has not missed them.

`make m9-compare JOB=<id>` produces three separate lists — matched, missed, and found-but-unexpected
— and refuses to flatter: a missed expectation is recorded as a **question** (did the crawl reach
it? was the budget exhausted? does the deployment differ?), not a verdict. Run against fixture
output it prints a warning that the comparison says nothing about live detection, and a test
asserts that warning appears.

---

## 5. Verification

| Check | Result |
|---|---|
| `tests/backend` + invariants | **269 passed, 9 skipped** (19 new M9 tests) |
| `scripts/net_verify.sh` | **115/115** |
| `make lint` / `make typecheck` | clean |
| `prove_authorisation_tamper.sh` | DENY on edit, PASS on revert |
| Live assessments ever run | **0** — asserted by a test that will fail the day M9 happens |

---

## 6. What remains, in order

1. **Sign §7** of `lab/authorisation/MOCK-WEB-001.md` by hand. Only you can.
2. `make attest-authorisation` — records the signed document's digest.
3. `POST /scope-grants/{id}/verify-document` with `signed=true` and that digest (admin).
4. `POST /scope-grants/{id}/activate` — **a second person**; the API refuses the requester.
5. Resolve the `0.0.0.0:5433` listener with its owner, then `make lab-check && make isolation-report`.
6. `ZAP_ADAPTER_ENABLED=true`, then `SCANNER_EXECUTION_ENABLED=true`, as separate decisions.
   `ACTIVE_SCAN_ENABLED` stays **false**.
7. `make m9-readiness` → expect 13/13.
8. Run `zap-passive` in **live** mode, then `make m9-compare JOB=<id>` and generate the report.

Steps 1 and 4 are the ones this platform must never do for you.
