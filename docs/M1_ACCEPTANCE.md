# M1 — Local Mock Website Lab: scope and acceptance criteria

**Not started.** Awaiting approval. Infrastructure and verification only — no backend, no API, no
scanner adapter code (those are M2/M5). M1's job is to build the isolated lab and **prove** its
isolation, including proving the proof can fail.

## 1. Deliverables

| # | Artefact | Notes |
|---|---|---|
| 1 | `docker-compose.lab.yml` | `vapt_lab` (`internal: true`, `172.30.10.0/24`), Juice Shop + ZAP, digest-pinned |
| 2 | `docker-compose.yml` | `vapt_edge` / `vapt_core` networks declared (services land in M2) |
| 3 | `lab/juiceshop/` | compose fragment + notes; container port 3000 published **only** on `127.0.0.1:3000`; network alias `shop.brakes-vapt.test` |
| 4 | `lab/zap/` | daemon config, `zap-baseline-policy.xml`, `excludes.txt`, rule denylist; API-key required; non-root, read-only rootfs + tmpfs, `cap_drop: ALL`, `no-new-privileges`, pid/memory/CPU limits; **no Docker socket** |
| 5 | `scripts/lab_isolation_check.sh` | the probe suite of §3, emitting machine-readable JSON |
| 6 | `scripts/lab_subnet_check.sh` | pre-`up` conflict detection for `LAB_SUBNET` |
| 7 | `Makefile` | `lab-up`, `lab-down`, `lab-check`, `lab-reset`, `lab-logs` |
| 8 | `lab/seed/MOCK-WEB-001.json` | asset + scope-rule fixture (**no grant activation** — see §5) |
| 9 | `.env.example` | lab variables with placeholders; no real secrets |
| 10 | `lab/README.md` | operator runbook incl. the `.test`-does-not-resolve-on-your-workstation note |
| 11 | `tests/lab/` | pytest wrappers around the probes so CI asserts the same facts |
| 12 | `backend/tests/invariants/` | suite skeleton + **manifest test** (I1–I14 with milestone map) and **I4 implemented** — see [INVARIANTS.md](INVARIANTS.md) |
| 13 | `lab/README.md` §Recovery | the operator-performed container restart runbook (`make lab-zap-restart` → `make lab-check`), and why `restart: "no"` means ZAP stays down after a crash |
| 14 | `make lab-zap-restart` | operator escalation target; the application itself has **no** container-control capability (no Docker socket) |

## 2. Functional acceptance criteria

| # | Criterion | Verification |
|---|---|---|
| F1 | Juice Shop starts and serves HTTP 200 on its root inside the lab network | `docker compose exec` curl from a lab-attached container |
| F2 | `shop.brakes-vapt.test` resolves **inside** `vapt_lab` to an address in `172.30.10.0/24` | `getent hosts` from a lab container; address asserted in-subnet |
| F3 | ZAP daemon responds to `/JSON/core/view/version` **with** the API key, and **refuses without it** | both directions asserted |
| F4 | The workstation reaches the app at `http://127.0.0.1:3000` | host-side curl |
| F5 | `shop.brakes-vapt.test` does **not** resolve on the host | host-side resolution must fail; no hosts-file entry is added |
| F6 | `make lab-reset` returns Juice Shop to a clean state | marker record created, reset, marker absent |
| F7 | `lab_subnet_check.sh` detects a conflicting subnet and refuses `lab-up` | run with a deliberately overlapping fixture |

## 3. Isolation acceptance criteria (the core of M1)

| # | Criterion | Verification |
|---|---|---|
| I1 | `vapt_lab` is `internal: true` with no gateway route | `docker network inspect` + no default route in a lab container |
| I2 | TCP egress from the **ZAP** container to each `ISOLATION_PROBE_TARGETS` entry fails | bounded-timeout connect attempts, all must fail |
| I3 | TCP egress from the **Juice Shop** container fails identically | same probes |
| I4 | Public DNS resolution fails from both containers | a public name must not resolve |
| I5 | No `/var/run/docker.sock` is present in either container | mount inspection + in-container stat |
| I6 | ZAP runs non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, with resource limits | container inspect assertions |
| I7 | The evidence volume is **not** mounted into any scanner container | mount inspection |
| I8 | The published port binds `127.0.0.1` only, not `0.0.0.0` | `docker port` + host-interface probe from the LAN address must fail |
| I9 | The probe suite writes a machine-readable result (the future `lab_isolation_checks` payload) with `egress_blocked`, `dns_contained`, `passed`, `valid_until` | schema-validated JSON |
| I10 | **A deliberately induced misconfiguration makes the check FAIL** — a check that cannot fail is not a check | attach a lab container to a bridge network with egress, re-run, assert `passed=false` and the failing probe named; then revert and assert `passed=true` |
| I11 | A stale result is treated as not-passed | timestamp older than `ISOLATION_CHECK_TTL_MINUTES` ⇒ `passed=false` |
| I12 | ZAP is configured `restart: "no"`, so a killed daemon stays down | kill the container; assert it does not return; assert `make lab-check` still reports correctly |
| I13 | No container-control capability exists in the lab definition | no Docker socket bind anywhere in either compose file; grep-level assertion in `tests/lab/` |

## 3a. Invariant acceptance criteria

| # | Criterion | Verification |
|---|---|---|
| V1 | **Invariant I4 passes** (no scanner-worker internet access) as an automated test, not only a script | `pytest backend/tests/invariants -k I4` in the lab job |
| V2 | **The manifest test passes**: all of I1–I14 are present, each skip names a milestone not yet landed, and no invariant is skipped past its milestone | `pytest backend/tests/invariants/test_manifest.py` |
| V3 | The I4 **failure** direction is proven (induced misconfiguration ⇒ test fails) and then reverted | recorded output of both runs |

## 4. Documentation acceptance criteria

D1 `lab/README.md` covers bring-up, teardown, reset, the isolation check and how to read its output ·
D2 the `.test` hostname behaviour (lab-only resolution; use `127.0.0.1:3000` from the workstation; no
hosts-file entry) is stated explicitly · D3 digests are recorded with the date pinned and the reason ·
D4 every M1 limitation is listed (below) · D4a the reset/recovery boundary is documented: the platform cannot restart containers, `POST /system/scanner/reset` (M5) never clears a dirty flag without full verification, and the operator restart path is the escalation · D5 `docs/` is updated if reality diverges from the design,
rather than the divergence being left undocumented.

## 5. Explicitly out of scope for M1 — and the standing denial

- **No scanning of any kind.** `SCANNER_EXECUTION_ENABLED=false`, `ZAP_ADAPTER_ENABLED=false`,
  `ACTIVE_SCAN_ENABLED=false`, `DEFAULT_SCANNER_ADAPTER=mock`. ZAP is started so its isolation can be
  proven, not used.
- **No ScopeGrant activation.** `lab/authorisation/MOCK-WEB-001.md` is an unsigned draft; it will not
  be signed, altered or auto-verified by this milestone, and the seed fixture contains asset and
  scope-rule data only. **Scanner execution therefore remains denied regardless of any flag.**
- No API, database, worker, adapter, agent or frontend code (M2+).
- No authenticated scanning, no Nuclei, no active profiles.

## 6. Known limitations to be recorded at M1 completion

1. Isolation is asserted for this host's Docker configuration at this date; it is re-verified by
   `make lab-check` rather than assumed to persist.
2. `internal: true` relies on the Docker daemon and host kernel (assumption B1) — not independently
   verifiable by this platform.
3. The probe suite is script-level in M1; wiring it to preflight gate 2 as a persisted
   `lab_isolation_checks` row happens in M3.
4. Juice Shop is deliberately vulnerable; it is disposable and must never be reachable off-host.
5. No evidence, scan data or report exists yet, so retention, redaction and dual control are
   unexercised at M1; invariants I1–I3 and I5–I14 are therefore skipped with milestone-referenced
   reasons, which the manifest test permits only until their milestones land.
6. ZAP is started solely so its isolation can be proven; there is no adapter, queue or API in M1, so
   no code path can scan. Scanner execution is denied by three independent facts: the implementation
   does not exist, the flags are false, and no signed authorisation or active grant exists.
7. The platform cannot restart its own containers (no Docker socket). Daemon recovery is an
   operator action; M1 documents the runbook but implements no reset endpoint (that is M5).

## 7. Milestone report (required on completion, per `CLAUDE.md` rule 15)

Files changed · commands run · pass/fail for every F/I/D criterion above with the actual output ·
image digests pinned · unresolved risks · confirmation that scanner execution remains disabled and no
grant was activated · next milestone (M2) scope.
