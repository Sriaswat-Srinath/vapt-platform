# Security Assumptions and Residual Risk (final, pre-M1 review)

> **Baseline notice (R2, 2026-11-12).** This file is the approved security-assumptions and
> residual-risk baseline. Nothing in it is to be weakened silently; a change requires an approved
> ADR. Section F carries the round-2 additions.

What the platform's safety claims depend on. Anything here that proves false invalidates a control,
so each assumption names its verification and what breaks if it fails.

## A. Assumptions that are mechanically verified

| # | Assumption | Verified by | If false |
|---|---|---|---|
| A1 | `vapt_lab` and `vapt_core` have no route off-host — **container→internet and container→LAN only; not host isolation (see §H)** | `make lab-check` / `POST /system/isolation/verify`: TCP probes to fixed public IPs and a public DNS lookup must all fail, from inside the ZAP container | gate 2 denies every scan; scanning stays disabled |
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

---

## F. R2 additions (2026-11-12)

### F.1 New mechanically verified assumptions

| # | Assumption | Verified by | If false |
|---|---|---|---|
| A11 | At most one ZAP job touches the daemon at a time | global advisory lock + partial unique index (one `held` lease per adapter) + a concurrent-submission test asserting the lease timeline | second job stays `queued`; `newSession` cannot run under another job |
| A12 | Unproven daemon state is never trusted | stale/unheld lease ⇒ daemon dirty; dirty blocks every job at gate 13; only an audited admin reset clears it | scanning stops platform-wide — the safe direction |
| A13 | Intrusive authority cannot be granted by configuration | effective dual control is computed at startup **and** at every gate 7 evaluation; five-case test matrix; forbidden config values refused at startup | flag forced false, audited; intrusive stays denied |
| A14 | An approval does not outlive its identities' qualification | eager invalidation on revoke/deactivate/unattest + live re-evaluation; in-flight jobs cancelled at the next cancellation checkpoint, bounded by `CANCELLATION_SLA_SECONDS` (A24) | approval `invalidated`; job stops with `approval_invalidated` |
| A15 | No plain hash of a secret value is ever exposed | keyed HMAC refs only; `LLM_EXPOSE_CONTENT_HASHES=false` not disableable; canary sweep over every tool result, prompt and error | CI fails; merge blocked |
| A16 | A blob is never unlinked while an active reference exists | FK + `SELECT … FOR UPDATE` with an in-transaction recount + post-unlink assertion; shared-blob and concurrent-reference tests | deletion skipped as `skipped_referenced`; no dangling reference |
| A17 | An interrupted purge resolves to a known state | plan committed before any destructive step; idempotent per-item steps; unlink-before-row-null so the failure mode is "file gone, row stale" (repairable) not "row purged, secret on disk" (silent failure); startup reconciler | reconciler completes or fails the item, audited |
| A18 | Scanner execution is denied while the authorisation document is an unsigned draft | DB CHECK (`state<>'active' OR document_state='signed_verified'`) + gate 5 re-verification + startup check for tampered grant rows | grant cannot activate; every scan denied |

### F.2 New assumption trusted by necessity

| # | Assumption | Residual risk | Containment |
|---|---|---|---|
| B7 | **Host full-disk encryption protects evidence at rest** | **The platform does not implement application-level encryption and does not verify FDE.** On a running host, FDE gives no confidentiality against root, container escape, a process that can read the volume, backup copies, misconfigured bind mounts, process memory, or database dumps. `SECRET_KEY`, `POSTGRES_PASSWORD`, `ZAP_API_KEY`, `REDACTION_HMAC_KEY` and the LLM key share this exposure | `EVIDENCE_ENCRYPTION_MODE=none` is reported verbatim by `/system/capabilities` and in every report's Limitations; blobs are `0600`, non-root-owned, never mounted into a scanner container; **MVP evidence is synthetic only**, which is why deferral is acceptable; envelope encryption + key management required before any non-synthetic data (open decision **D13**) |

### F.3 Additions to the accepted limitations (§C)

11. **One ZAP job at a time, platform-wide.** Queued jobs wait; this is a deliberate isolation
    trade, not a defect.
12. **A crashed scanner worker requires an audited admin reset**, because the previous job's teardown
    is unproven and daemon state is therefore untrusted. No auto-recovery.
13. **Purge is final.** No restoration capability exists in the MVP; the controlled request flow
    exists only so that any future restoration from an operator-managed backup is verified and
    audited rather than ad hoc.
14. **Report generation does not extend the life of unredacted evidence** (`pins_blob=false`), so a
    long-lived report pins redacted text only.
15. **Rotating `REDACTION_HMAC_KEY` ends correlation with pre-rotation refs.** Preserving it would
    require retaining the secrets, which is refused.
16. **Evidence is not encrypted at application level** (B7 above), stated in every report.
17. **Scanner execution is currently denied in this repository**, because
    `lab/authorisation/MOCK-WEB-001.md` is an unsigned draft and no grant can be activated from it.

---

## G. R3 additions (2026-11-12)

### G.1 New mechanically verified assumptions

| # | Assumption | Verified by | If false |
|---|---|---|---|
| A19 | Evidence can only originate from a registered mock asset | worker-only writes with `raw_observations.job_id NOT NULL`; no import/upload path; ingestion rejects peer IP ∉ `pinned_ips` or host/port mismatch; `GET /system/provenance/verify` walks the full chain | observation rejected and audited; a violating finding is quarantined and excluded from reports (I1, I14) |
| A20 | Asset identity cannot be relabelled | BEFORE UPDATE trigger on `environment`/`hostname`/`protocol`/`port`; PATCH whitelist excludes them; and relabelling changes nothing because gates 8–10 plus the lab-only route still decide reachability | update rejected; the route still denies a non-lab target (I14) |
| A21 | A purge never leaves a secret on disk while the database claims it is gone | intent committed before any filesystem change; pre-unlink identity checks; post-unlink absence check; directory `fsync`; row updated only afterwards; crash-recovery matrix replayed at every boundary | the inverse inconsistency is unreachable by construction; the reachable one ("bytes gone, row stale") is detected and repaired, and any unexplained state halts further deletion (I12) |
| A22 | A dirty daemon cannot be cleared without verification | nine-step reset, all steps must pass; no force parameter, no override, no expiry; `SCANNER_RESET_REQUIRES_VERIFICATION` not disableable | flag stays set; gate 13 keeps denying every job (I8) |
| A23 | Incomplete coverage cannot produce a confirmed finding | negative-evidence rules suppressed when `coverage_complete=false`; `coverage_complete` recorded as a rule input | finding resolves `inconclusive` with `reason='incomplete_coverage'` |
| A24 | Cancellation terminates within a bounded time | per-step timeouts summing below `CANCELLATION_SLA_SECONDS`; startup refuses an unreachable SLA | `cancel_unconfirmed` + dirty daemon + alert — never an indefinite wait (I13) |
| A25 | The HMAC key never leaves the api process | `SecretBytes` type, log scrubber, id-only config introspection, key registered as a mandatory redactor canary; never persisted | CI fails; the canary redacts and alerts (I11) |

### G.2 New assumptions trusted by necessity

| # | Assumption | Residual risk | Containment |
|---|---|---|---|
| **B8** | **Direct database and Docker-daemon access are not misused** | An actor with DB access can forge rows (including an `environment` label) or rewire networks, so the synthetic-only property cannot be *proven* against an insider with that access | Forgery must be **consistent across** the job, scope decision, pinned IPs, resolution history and the covering isolation record; the append-only audit hash chain (`/audit/verify`) and `asset_resolutions` history make disagreement visible; `environment` is immutable through the application; the lab-only route means no real target was ever reachable from the worker. **Containment, not elimination** |
| **B9** | **ZAP process death cannot be verified at OS level** | Verifying process liveness needs the Docker socket, which is permanently prohibited, so "the old daemon is gone" is inferred from daemon identity and state rather than observed | Instance-marker context + recorded version/session; any absence or mismatch ⇒ dirty; `restart: "no"` prevents a silent auto-restart presenting a deceptively clean session; recovery requires a verification-gated reset and, where applicable, an explicit operator container restart |

### G.3 Additions to the accepted limitations (§C)

18. **The platform cannot restart its own scanner container.** Recovery from a daemon crash requires
    an operator-performed `make lab-zap-restart` followed by `make lab-check` and a verification-gated
    reset. This is a deliberate consequence of prohibiting Docker socket access.
19. **Synthetic-only cannot be proven against privileged insiders** (B8); it is enforced by route and
    ingestion controls, and inconsistency is made detectable.
20. **Process liveness is not verified** (B9); daemon identity and state are.
21. **A halted retention state blocks all further deletion** until an admin acknowledges — evidence
    may therefore persist beyond its retention window while an inconsistency is unresolved. Chosen
    deliberately over continuing to delete past an unexplained state.


---

## H. After M1 (2026-11-12) — measured reachability and ratified deviations

### H.1 Reachability classes (do not conflate)

| Class | Measured | Protection relied upon |
|---|---|---|
| container → internet | `ENETUNREACH` (blocked) | no default route + forwarded-traffic isolation (A1, I4) |
| container → LAN / LAN gateway | `ENETUNREACH` (blocked) | same |
| container → host via host LAN IP / `docker0` | `ENETUNREACH` (blocked) | no route |
| **container → host via lab gateway `172.30.10.1`** | **reachable** for host services bound on `0.0.0.0` | **operator hygiene + probes `I14`/`I14b`**; scope gates never allow the gateway as a target |
| container → container (same lab) | reachable | ZAP `api.addrs` allowlist + key; target is disposable |
| container → other Docker network | blocked | no route |
| **host → container** | **reachable** on container IPs | ZAP `api.addrs` excludes the host (`I9c`); the target is synthetic |
| LAN peer → container | not without host routing | loopback-only publishes (`I14`); `ip_forward=1` on this host is noted |

**`internal: true` is never described as complete host isolation.**

### H.2 New verified assumptions

| # | Assumption | Verified by | If false |
|---|---|---|---|
| A26 | No VAPT component is published on `0.0.0.0` | probe `I14`; host-wide `0.0.0.0` listeners reported by `I14b` | isolation check fails |
| A27 | The workstation forwarder relays only to the registered target | fixed destination with refusal of every other address class; proxy-abuse test; established-peer check | forwarder refuses to start / test fails |
| A28 | A restart acknowledgement cannot clear dirty state or be reused | consulted only by R3; single-use, atomic, TTL, identity-bound; tamper matrix tests | reset fails at R3; flag retained |
| A29 | ZAP's writable surface is three size-capped, `nosuid`, uid-owned tmpfs paths | container inspect + `read_only: true` probe `I6b` | — |

### H.3 New assumption trusted by necessity

| # | Assumption | Residual risk | Containment |
|---|---|---|---|
| B10 | The host operator does not bind unrelated services on `0.0.0.0` | lab containers (and thus a compromised scanner) could reach such a service via the gateway | `I14b` reports every such listener on each check; the lab target is synthetic; scope gates refuse the gateway IP as a target |

### H.4 Additions to the accepted limitations (§C)
22. `internal: true` provides no host isolation; see H.1.
23. `/tmp` in the ZAP container is executable (JVM requirement), on a size-capped `nosuid` tmpfs.
24. Workstation access to the target requires an explicit operator step (`make lab-publish`).


---

## I. After M1.5 (2026-11-17) — application plane and egress boundary

### I.1 New verified assumptions

| # | Assumption | Verified by | If false |
|---|---|---|---|
| A30 | The api has no route to the internet | `NET-H1` (`ENETUNREACH`), `NET-F:api` (no default route); api is on internal networks only | `net_verify` fails |
| A31 | The worker cannot reach the internet, the LAN, the egress proxy or the api | `NET-G1`…`NET-G5`, `NET-G7`; induced-failure proof flips `NET-G1`/`NET-G2` | `net_verify` fails |
| A32 | The api's HTTP listener is bound to its `vapt_edge` address only — proven **from the worker's perspective** | `NET-G5` returns `ECONNREFUSED` from `vapt_core`; `NET-J8` likewise from the proxy | `net_verify` fails |
| A33 | Outbound traffic is `CONNECT`-only to one exactly-matched `host:port`; every other host, port and method is refused and logged | `NET-J1`…`NET-J6`, `NET-J10`/`J10b`; 48 denials recorded in M1.5 | `net_verify` fails |
| A34 | The egress proxy cannot reach application or scanner components | `NET-J7*`, `NET-J9*` (blocked), `NET-J8` (no listener) — **note the mechanism in I.2** | `net_verify` fails |
| A35 | The WAN side cannot use the proxy | `NET-J11` (`ECONNREFUSED`; the proxy binds one interface) | `net_verify` fails |
| A36 | No real LLM provider is contacted by tests | `NET-K2` (allowlist is the local stand-in only), `NET-K3` (no permitted tunnel elsewhere in the decision log), `NET-K4` (every permitted tunnel resolved to `172.30.23.70`) | `net_verify` fails |
| A37 | Attachment sets, image digests, environment, publishing and socket absence are as specified | `NET-A:*`, `NET-B:*`, `NET-C:*`, `NET-D:*`, `NET-E:*` | `net_verify` fails |

### I.2 Mechanism distinction (recorded, not glossed)

The egress proxy **must** have a default route. Consequently its packets toward an internal VAPT
subnet are not rejected with `ENETUNREACH`: they leave via the default route, reach the host (which
has routes to those bridges, with `ip_forward=1`), and are **silently dropped by Docker's
inter-network isolation rules** — the observed class is a timeout. The destination is unreachable
either way, but for the proxy this rests on **iptables rules rather than the absence of a route**.
Every other component has no default route at all (`NET-F:*`), which is the stronger property.
Probes `NET-J7*`/`NET-J9*` accept `ENETUNREACH | TIMEOUT` and state the mechanism.

| # | Assumption | Residual risk | Containment |
|---|---|---|---|
| B11 | Docker's inter-network isolation rules remain in force on this host | if flushed, the proxy (the only container with a default route) could reach internal subnets via the host | the proxy runs one auditable CONNECT-only program with an exact allowlist, non-root, read-only, `cap_drop: ALL`; `net_verify` re-measures the property and fails if it changes; every other component has no route at all |

### I.3 Additions to the accepted limitations (§C)
25. The proxy's inability to reach internal subnets rests on Docker's isolation rules, not on absent
    routing (I.2, B11).
26. `net.ipv4.ip_forward` is `1` on this host; recorded in every network result rather than relied upon.
27. M1.5 services are **placeholders**: they prove topology, not application behaviour. No endpoints,
    no migrations, no authentication, no scanner adapter.
