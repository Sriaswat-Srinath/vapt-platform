# M1 Completion Report — Isolated Local Mock Laboratory

Baseline: approved M0 commit `329c67c`. Scope: lab only. **Scanner execution remains disabled; the
authorisation document is untouched and unsigned; no ScopeGrant exists.**

## 1. Deviations requiring your ratification

### D19 — Docker silently ignores `ports:` on an `internal: true` network

**What the design said.** `ARCHITECTURE.md` and `CONFIGURATION.md`: Juice Shop publishes container
port 3000 on `127.0.0.1:3000`.

**What is actually true.** Docker accepts the `ports:` declaration and records it in
`HostConfig.PortBindings`, then **silently creates no binding** for a container attached only to an
internal network. Verified:

```
HostConfig.PortBindings : {"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"3000"}]}   <- requested
NetworkSettings.Ports   : {"3000/tcp":null}                                         <- not created
docker port vapt_juiceshop → (empty)       ss -lntp | :3000 → (nothing listening)
pgrep docker-proxy → only unrelated projects (:8091, :3001)
curl http://127.0.0.1:3000/ → 000 (unreachable)
curl http://172.30.10.20:3000/ → 200 (host reaches the container directly)
```

No error, no warning. This is the dangerous kind of failure: a config that reads as correct and does
nothing.

**Options considered.**

| Option | Verdict |
|---|---|
| Attach Juice Shop to a second, non-internal network | **Rejected** — gives the target egress and breaks I3 |
| Non-internal bridge with `enable_ip_masquerade=false` | **Rejected** — blocks the public internet but **not the local LAN**; I measured the LAN direction and it must stay blocked |
| Dual-homed forwarder container (lab + publish network) | **Rejected** — puts a container with egress inside the lab; a compromise of it bridges the boundary |
| **Host-side loopback forwarder (chosen, opt-in)** | `scripts/lab_publish.py`, started by `make lab-publish` |

**Why the chosen option does not weaken isolation.** The host can *already* reach the lab bridge
directly (measured above: `172.30.10.20:3000` → 200, because `internal: true` blocks forwarded
traffic, not host-local routing). A host-local, inbound-only forwarder to one fixed destination
therefore grants **no container any capability it did not already have**. No container is dual-homed,
so nothing bridges the lab to a network with egress; traffic flows host → lab only. It binds
`127.0.0.1` exclusively (not parameterised), is opt-in, and is reversible with `make lab-unpublish`.
Verified: `F4` 200 via loopback, `F4b` zero non-loopback listeners, `F4c` the LAN interface
`192.168.1.9:3000` does **not** serve the app.

**Request:** ratify D19, or tell me to drop workstation access entirely (then F4 is withdrawn and the
operator uses `http://172.30.10.20:3000`, which needs no forwarder).

### D20 — `internal: true` does not isolate containers from the host

Worth recording as an architectural fact, not a defect: the host reaches lab containers directly on
the bridge. Our egress claims are unaffected (container → anywhere off-host is blocked, measured in
three directions: public IP, public DNS, and the LAN gateway). But it means **network isolation alone
never protected the ZAP API from the workstation.** That is precisely what ZAP's `api.addrs`
allowlist does, and it is now proven to do it (§6, I9c). `SECURITY_ASSUMPTIONS.md` A1 should gain
this clarification; I have not edited it pending your ratification.

### D21 — Juice Shop v17 is a distroless image

No shell, no `node` on `$PATH` (binary at `/nodejs/bin/node`), runs as uid 65532. Better hardening
than the design assumed, but it broke the healthcheck and the in-container probes as first written;
both now use the explicit interpreter path. No security trade-off — recorded so the dependency is not
"fixed" later by swapping to a shell-bearing image.

### D22 — ZAP `read_only: true` needs explicitly-owned tmpfs

A tmpfs declared with options defaults to root-owned `0755`, which the non-root `zap` user cannot
write (`Unable to create home directory /home/zap/.ZAP/`). Resolved with
`uid=1000,gid=1000,mode=0770` on `/home/zap`, `/tmp`, `/zap/wrk`; `read_only` rootfs and `nosuid`
retained. `noexec` on `/tmp` was dropped because the JVM needs it — a deliberate, narrow relaxation
on a tmpfs inside a `cap_drop: ALL`, non-root, read-only-rootfs container.

## 2. Pinned images (by digest)

| Component | Image |
|---|---|
| Juice Shop | `bkimminich/juice-shop@sha256:9e437b456e444ff001d1663e4f6f05c796fe02f1058dd2651d6791a15b43dfeb` (v17.1.1) |
| ZAP | `ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af` (2.17.0) |

## 3. Network topology

```
vapt_lab   internal: true   172.30.10.0/24   no default route · no egress · no DNS leak
  ├── vapt_zap        172.30.10.10:8080   API — NO published port, api.addrs allowlist, API key
  └── vapt_juiceshop  172.30.10.20:3000   alias shop.brakes-vapt.test  (lab-only resolution)

host ──(opt-in loopback forwarder, inbound only)──▶ 172.30.10.20:3000
declared for M2: vapt_edge (only egress, LLM provider) · vapt_core (internal: true)
```

Neither lab container is dual-homed — asserted by probes I8b and I8e.

## 4. Container security configuration

| Control | ZAP | Juice Shop |
|---|---|---|
| user | `zap` (uid 1000), non-root | uid 65532, non-root (distroless) |
| read-only rootfs | **yes** (tmpfs `/home/zap`, `/tmp`, `/zap/wrk`, uid-owned, `nosuid`) | no — the app writes its own SQLite/uploads; it is the disposable target, not the scanner |
| `cap_drop: ALL` | yes | yes |
| `no-new-privileges` | yes | yes |
| pids / memory / cpu | 512 / 2 GiB / 2.0 | 256 / 1 GiB / 1.5 |
| host bind mounts | **none** | **none** |
| Docker socket | **absent** (declaration, mounts, and in-container stat all checked) | **absent** |
| published ports | **none** | **none** (see D19) |
| restart policy | **`no`** | `no` |
| ZAP API access | not published + `api.addrs` allowlist (worker range `.3x` only; host `.1` excluded) + API key | — |

## 5. Results — functional (F1–F7)

| # | Criterion | Result | Evidence |
|---|---|---|---|
| F1 | Juice Shop reachable inside the lab by `shop.brakes-vapt.test` | **PASS** | probe `F1` REACHABLE |
| F2 | hostname resolves in-lab to an in-subnet address | **PASS** | `I10a` → `172.30.10.20` |
| F3 | ZAP API: accepts allowlisted in-lab client with key; rejects without key | **PASS** | `I9a` HTTP 200 `{"version":"2.17.0"}`; `I9b` connection reset (no 200) |
| F4 | workstation reaches `http://127.0.0.1:3000` | **PASS, via D19 forwarder** | `F4` 200; `F4b` zero non-loopback listeners; `F4c` LAN interface does not serve |
| F5 | hostname does **not** resolve on the host | **PASS** | `I10b` UNRESOLVED |
| F6 | `make lab-reset` returns a clean state | **PASS** | exercised by `test_lab_reset_cannot_delete_unrelated_developer_data` |
| F7 | subnet conflict refuses `lab-up` | **PASS** | `172.17.0.0/16` refused naming `bridge`+`docker0`; own subnet reported free even while the lab is up (bug found and fixed: the lab's own bridge route was a false conflict) |

## 6. Results — isolation (I1–I13)

| # | Criterion | Result | Evidence |
|---|---|---|---|
| I1 | `internal: true`, no default route in **either** container | **PASS** | `I1a` true; `I1b`/`I1d` `NONE` from `/proc/net/route` |
| I2 | egress blocked from ZAP — public IPs **and LAN gateway** | **PASS** | `I2:1.1.1.1:443`, `I2:8.8.8.8:53`, `I2L:192.168.1.1:80` all BLOCKED |
| I3 | egress blocked from Juice Shop — same three directions | **PASS** | `I3:*`, `I3L:*` BLOCKED |
| I4 | public DNS fails from both | **PASS** | `I4a`, `I4b` UNRESOLVED |
| I5 | Docker socket absent | **PASS** | no bind in either container's mounts; `stat /var/run/docker.sock` ABSENT inside ZAP |
| I6 | ZAP hardened | **PASS** | user `zap`, read-only rootfs `true`, `cap_drop` **exactly `ALL`**, `no-new-privileges:true`, pids 512, mem 2 GiB |
| I7 | no host bind mounts into lab containers | **PASS** | `I7:*` `<none>` |
| I8 | Juice Shop not on 0.0.0.0; neither container dual-homed; **ZAP API port not published**; host `127.0.0.1:8080` refused | **PASS** | `I8a`–`I8e` |
| I9 | ZAP API: key required; **host (gateway `.1`) refused even with a valid key** | **PASS** | `I9c` != 200; zap.log: `Request … from 172.30.10.1 not permitted` |
| I10 | alias contained | **PASS** | in-lab in-subnet; not on host |
| I11 | stale result treated as not-passed | **PASS by construction** | `valid_until` emitted; consumer rule specified for M3 |
| I12 | killed ZAP stays down; no automatic restart | **PASS** | 30 s observation after `docker kill`, `running=false` throughout; restart policy `no` |
| I13 | no container-control capability in the lab definition | **PASS** | no `docker.sock` in either compose file; ZAP service has no `ports:` in rendered config |

## 7. Results — invariants (V1–V3)

| # | Criterion | Result |
|---|---|---|
| V1 | **I4 passes as an automated test** against the running lab | **PASS** — `test_i4_no_scanner_egress.py`, 6 assertions |
| V2 | manifest: I1–I14 declared; each skip names a milestone not yet landed; nothing skipped past its milestone | **PASS** — 13 skipped = exactly the 13 invariants not yet due |
| V3 | I4's **failure direction** proven and reverted | **PASS** — §8 |

`pytest tests/lab backend/tests/invariants`: **47 passed, 13 skipped, 0 failed** (isolation 42+13, recovery 5).

## 8. Induced isolation failure — actual evidence

`scripts/prove_isolation_failure.sh`, 2026-11-12 06:51 UTC. Raw files: `docs/evidence/m1/`.

```
PHASE 1  baseline           isolation_passed=True   failing=0
PHASE 2  docker network connect bridge vapt_zap     ("default route now present via eth1")
PHASE 3  induced            isolation_passed=False  failing=6
           I1b                  required=NONE        observed=eth1:010011AC
           I2:1.1.1.1:443       required=BLOCKED     observed=REACHABLE
           I2:8.8.8.8:53        required=BLOCKED     observed=REACHABLE
           I2L:192.168.1.1:80   required=BLOCKED     observed=REACHABLE   <- corporate-LAN direction
           I4a                  required=UNRESOLVED  observed=RESOLVED
           I8e                  required=vapt_lab    observed=bridgevapt_lab  <- dual-homing detected
PHASE 4  docker network disconnect bridge vapt_zap  ("no default route — reverted")
PHASE 5  reverted           isolation_passed=True   failing=0
VERDICT  PROVEN
```

Six independent probes flipped, including the LAN direction and the topology probe. `access_passed`
stayed `True` throughout — the convenience path correctly has no bearing on the isolation verdict.

**A defect this proof caught in my own check:** the original `I1b` probe used `ip route`, which the
ZAP image does not ship; the probe errored silently and would have *passed* with a default route
present. It now reads `/proc/net/route`, a probe error is recorded as a failure, and `I1b` is among
the six that flip above. This is exactly why the failure direction is a release blocker.

## 9. Recovery results (release blockers)

| Blocker | Result | How |
|---|---|---|
| ZAP crash → daemon stays down | **PASS** | `docker kill`, 30 s observation, `running=false`; policy `no` |
| dirty daemon cannot be cleared without verification | **PASS** | unreachable daemon ⇒ fails R2, flag retained, `requires_operator_restart`; **unacknowledged restart ⇒ fails R3, flag retained**; documented `make lab-zap-restart` + `make zap-reset` ⇒ R2–R7 pass, flag cleared; consumed acknowledgement **cannot be replayed**; no force path exists |
| reset cannot delete unrelated developer data | **PASS** | sentinel volume + network survive `make lab-reset`; no unrelated network/volume/image removed; Makefile contains no `prune` |

Every daemon-state transition is appended to `zap-daemon-audit.log` (copy in `docs/evidence/m1/`).

### D23 — identity after an authorised restart (clarifies ADR-0008 R3 §10, needs ratification)
The ADR did not say how an *authorised* restart is distinguished from an unexplained one; a
restarted daemon always lacks its instance marker. Implemented: `make lab-zap-restart` records a
**one-shot acknowledgement bound to the container's new `StartedAt`**; R3 accepts a missing marker
only when that acknowledgement matches, then consumes it. Any other restart fails R3. Property
proven by test: *restarting the container can never launder a dirty daemon.*

## 10. Defects found and fixed during M1 (my own)

| Defect | Fix |
|---|---|
| `NODE_ENV=unsafe` on the target re-enabled challenges Juice Shop disables in Docker for safety | removed |
| `I1b` false-pass (no `ip` binary) | `/proc/net/route`; probe error ⇒ fail |
| `I4b` malformed row flipped `dns_contained` | probe rewritten; row writer sanitises and fails malformed rows |
| `I6c` accepted any `cap_drop` | must be exactly `ALL` |
| subnet check reported the lab's own bridge route as a conflict | own bridge excluded by network id |
| `curl` probes emitted `000000` | fallback pattern fixed |
| trailing whitespace in observed values broke exact-match tests | `printf`-based emission |
| ZAP `api.addrs` lacked ZAP's own address (Host-header check) | explicit indexed entries; host `.1` still excluded |
| ZAP tmpfs root-owned under `read_only` | `uid/gid/mode` on tmpfs; `noexec` dropped on `/tmp` for the JVM |
| recovery tests bypassed the documented restore path | use `make lab-zap-restart` + `make zap-reset`; baseline asserted |
| state path hardcoded; no transition audit | `LAB_STATE_DIR` honoured; audit log |
| `lab-down` left the forwarder running | `lab-down` depends on `lab-unpublish` |

## 11. Remaining limitations and open items

1. **D19 needs ratification** (host-side forwarder). Until then `make lab-up` exposes nothing on the
   workstation; `make lab-publish` is a separate, reversible step.
2. **D20**: `internal: true` does not isolate containers from the host. Egress claims are unaffected;
   `SECURITY_ASSUMPTIONS.md` A1 should be clarified once you ratify the wording.
3. **D23** (one-shot restart acknowledgement) should be folded into ADR-0008 as an amendment.
4. **Juice Shop is not `read_only`** — it writes its own SQLite/uploads. It is the disposable target,
   not the scanner; recorded, not hidden.
5. ZAP's internal callback service listens on `0.0.0.0:44701` *inside* the container; unpublished and
   unreachable from the host (lab-only). Noted for M5's adapter design.
6. Isolation is asserted for this host's Docker 29.1.3 configuration on 2026-11-12 and re-verified by
   `make lab-check`, never assumed to persist (B1).
7. Disk: the host is at ~94% with the 3.75 GB ZAP image pulled. Not a safety issue; an operational one.
8. No evidence, scan data or report exists, so I1–I3 and I5–I14 remain milestone-pending skips, which
   the manifest test permits only until their milestones land.
9. **Nothing scanned. Flags unchanged: `SCANNER_EXECUTION_ENABLED=false`, `ACTIVE_SCAN_ENABLED=false`,
   `DUAL_CONTROL_AVAILABLE=false`. `MOCK-WEB-001.md` unsigned and untouched. No ScopeGrant exists.**

**Failed tests at completion: none.**


---

## 12. Post-acceptance addendum (ratification conditions, 2026-11-12)

| Deviation | Condition | Implemented | Verified by |
|---|---|---|---|
| D19 | fixed destination IP+port, loopback-only, no proxying, explicit shutdown, no auto-start, **negative test for unrelated destination** | `scripts/lab_publish.py` takes no arguments; refuses hostnames, the gateway, anything outside `LAB_SUBNET`; literal `127.0.0.1`; `lab-down` stops it | `test_forwarder_and_pinning.py` — 8 refusal cases, proxy-abuse (CONNECT / absolute-URI), established-peer check, no auto-start |
| D20 | distinguish the reachability classes; never call `internal` host isolation | measured matrix (including a controlled `0.0.0.0` host listener) recorded in every check as `reachability_matrix`; new probes `I14`/`I14b` | `SECURITY_ASSUMPTIONS.md` §H, `SAFETY.md` §9.1, ADR-0012 |
| D21 | keep digest pinning + reproducible startup/reset | unchanged | `test_lab_images_are_digest_pinned`, `test_running_containers_match_pinned_digests`, reset-scoping test |
| D22 | document JVM needs, writable paths, permissions, why `noexec` was removed | ADR-0008 R4 §15, `lab/README.md` | probe `I6b` |
| D23 | bind to container_id, started_at, daemon_instance_uuid, nonce, operator identity, timestamps; single-use, atomic, short-lived; mismatch invalidates; never clears dirty alone | `scripts/zap_daemon_state.sh` (`ack-restart`, R3, R7) | `test_restart_acknowledgement.py` — 9 cases incl. tamper matrix, TTL, unused-ack invalidation, never-clears-dirty; recovery suite |

**Preserved:** `docs/evidence/m1/` untouched; the induced-failure test retained (`make
lab-prove-failure`, run again after these changes); the 13 milestone-aware invariant skips unchanged;
no skipped invariant converted to a pass.

**Re-verified after the changes:** flags all `false`; `MOCK-WEB-001.md` byte-identical to commit
`83497ce`; `scope_grant: null`; ZAP reports zero active scans, zero spider scans, zero alerts, zero
messages (§13 below records the actual query output).

## 13. No-scan verification — asked of the daemon itself (2026-11-12, after all suites)

```
active scans  : {"scans":[]}
spider scans  : {"scans":[]}
alerts        : {"numberOfAlerts":"0"}
sites         : {"sites":[]}
messages      : {"numberOfMessages":"0"}
```

Queried from an allowlisted in-lab client after the full test run (which itself starts no scan). Flags `SCANNER_EXECUTION_ENABLED`, `ZAP_ADAPTER_ENABLED`, `ACTIVE_SCAN_ENABLED`, `DUAL_CONTROL_AVAILABLE` are `false` in both `.env` and `.env.example`; `lab/authorisation/MOCK-WEB-001.md` is byte-identical to commit `83497ce`; `scope_grant` is `null` and no grant file is tracked.

Final run after ratification changes: **39/39 probes**, induced failure flips 6 probes and recovers, **69 passed / 13 skipped / 0 failed** (`tests/lab` + `backend/tests/invariants`).
