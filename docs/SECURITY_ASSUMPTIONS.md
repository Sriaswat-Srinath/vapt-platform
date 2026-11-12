# Security Assumptions and Residual Risk (final, pre-M1 review)

What the platform's safety claims depend on. Anything here that proves false invalidates a control,
so each assumption names its verification and what breaks if it fails.

## A. Assumptions that are mechanically verified

| # | Assumption | Verified by | If false |
|---|---|---|---|
| A1 | `vapt_lab` and `vapt_core` have no route off-host | `make lab-check` / `POST /system/isolation/verify`: TCP probes to fixed public IPs and a public DNS lookup must all fail, from inside the ZAP container | gate 2 denies every scan; scanning stays disabled |
| A2 | `shop.brakes-vapt.test` resolves only inside `vapt_lab`, to a lab-subnet address | isolation probe + `asset_resolutions` history | gate 8 denies: resolution outside `allowed_cidrs` |
| A3 | No Docker socket is visible to a scanner container | isolation probe asserts absence of the bind | check fails ⇒ scanning disabled |
| A4 | The mock target is published on loopback only | startup validation rejects non-loopback `MOCK_TARGET_PUBLISH` | app refuses to start |
| A5 | `172.30.10.0/24` does not conflict with an existing network | checked 2026-11-12 (free: host uses `172.17–172.19/16`, `192.168.1.0/24`); re-checked by `make lab-check` before every `lab-up` | compose fails loudly; subnet is reconfigured via `LAB_SUBNET` |
| A6 | The agent cannot reach the network, a shell, or a write repository | import-linter contracts + the absence of such tools in the catalogue + tests asserting each forbidden action fails | CI fails; merge blocked |
| A7 | The LLM never receives unredacted text | `RedactedText` is constructible only by the redactor; import-linter forbids `agent/` importing blob/evidence readers; `redaction_report` per tool call | CI fails; merge blocked |
| A8 | The agent cannot change validation state, severity, confidence, CVSS, EPSS, KEV or priority | DB CHECK on `validation_events.actor_kind` + output guard field stripping + tests | DB rejects the write |
| A9 | A scan cannot start without an allow `ScopeDecision` persisted first | preflight chain is a pure total function; adapters re-check the decision | job denied, decision + audit row written |
| A10 | Audit log is append-only and tamper-evident | hash chain + `GET /audit/verify`; app DB role lacks UPDATE/DELETE on the table | verification reports the first divergence |

## B. Assumptions trusted by necessity (not verifiable by this platform)

| # | Assumption | Residual risk | Containment |
|---|---|---|---|
| B1 | The Docker daemon and host kernel correctly enforce network and container isolation | a container-escape or daemon bug defeats L1/L2 | non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, resource limits, no socket; the lab target is disposable and synthetic |
| B2 | Pinned image digests correspond to the intended upstream builds | a compromised upstream build predating our pin | digest pinning, `pip-audit`/`npm audit`/`bandit` in CI, no build-time network in the scanner image |
| B3 | Operators hold their API tokens securely | token theft ⇒ actions attributed to that identity | Argon2 hashes, expiry, revocation, `last_used_at`, per-call audit with token id |
| B4 | The configured LLM provider does not act on content sent to it in ways harmful to us | provider-side retention/logging of prompts | two-stage redaction (ADR-0010), id-based citation style, `LLM_ENABLED=false` default, synthetic-only MVP data |
| B5 | The authorisation document reflects a real, current authorisation | a stale or unauthorised document | SHA-256 recorded in the grant and re-verified at gate 5; validity window; revocation |
| B6 | Attested operator identities are distinct humans | collusion or a false attestation | attestation records who claimed it and when; **ADR-0009 refuses to call it independent dual control** and labels approvals `simulated_dual_control` when unavailable |

## C. Accepted limitations of the MVP (stated in every generated report)

1. **Single-operator dual control is unavailable.** Intrusive and active scanning are therefore
   disabled, not merely discouraged. No simulated approval is represented as independent approval.
2. **Unauthenticated coverage only** (D6). Authentication entry points are inventoried but the
   authenticated surface behind them is **unassessed**, not "clean".
3. **Passive and local-baseline scanning only.** Absence of a finding is not evidence of absence of a
   vulnerability; active-only detections are out of scope by design.
4. **No JavaScript rendering in discovery.** SPA routes appear only via linked assets and API
   responses, so the discovered surface understates a JS-heavy application.
5. **Synthetic target only.** All evidence is from a deliberately vulnerable Juice Shop instance.
   Findings say nothing about any real Brakes India system; the authorisation document explicitly
   grants no such scope.
6. **Threat intelligence may be absent or stale.** Missing EPSS/KEV yields NULL — never an estimate —
   and staleness is flagged.
7. **Validation rule coverage is partial.** Uncovered categories remain `candidate` with the evidence
   gap recorded; this reads as under-reporting and is intentional.
8. **Agent answers are advisory**, citation-bound, labelled AI-generated in reports, and cannot change
   any status.
9. **Single-host storage.** Losing the evidence volume loses evidence content while leaving findings
   and provenance hashes intact.
10. **ZAP daemon reuse** means job isolation depends on our teardown code (ADR-0008); it is tested by
    a consecutive-jobs contamination test and guarded by a daemon-dirty flag, but it is weaker than a
    container per job.

## D. Explicitly out of scope (will not be implemented)

DoS or stress testing · destructive or state-mutating exploitation · brute force or credential
stuffing · persistence or backdoors · credential theft · data exfiltration · malware · detection
evasion · exploitation beyond proof-of-presence · scanning of any non-registered, non-mock target ·
IoT/OT/firmware/infrastructure testing. These are excluded by profile policy, method denylist, rule
denylist and scope gates — each independently sufficient.

## E. Change control

These assumptions, the approved decisions (`DECISION_LOG.md`) and ADR-0001…0011 are binding. If an
implementation would weaken any control or a decision proves technically infeasible, work stops and
the trade-off is presented for approval before anything changes (`CLAUDE.md` rule 16). No silent
substitutions.
