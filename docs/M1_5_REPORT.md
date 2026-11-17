# M1.5 Completion Report — network architecture corrections and verification

Baseline: `5168dac`. **Topology and verification only.** No application endpoints, no migrations, no
authentication, no scanner adapter, no discovery, no scan, no real LLM call. Flags `false`.
Authorisation document unchanged.

## 1. The five corrections

| # | Correction | Implementation | Verified by |
|---|---|---|---|
| 1 | Resolve the `I14` collision; preserve history and invariant meanings | probes renamed `I14`→`PUB-1`, `I14b`→`PUB-2`; namespaces documented (`INVARIANTS.md` §0); M1 lab ids frozen; M1.5 uses `NET-*` | archived evidence unchanged (37 probes, no `I14`); lab re-check 39/39; `test_probe_ids_do_not_collide_with_invariants` |
| 2 | Host-gateway reachability for api/worker/frontend; record `ip_forward`; distinguish gateway from LAN; no claim of complete host isolation | `NET-HG:{api,worker,frontend}:{gateway,lan-ip}`; `ip_forward` in every result; explicit note field | all pass; `test_result_records_ip_forward_and_host_isolation_note` |
| 3 | Explicit test-only stand-in; permitted and denied destinations/ports/methods; never contact the real provider | `llm-standin:8443` on `vapt_wan`; `EGRESS_ALLOWLIST` exact-match; `NET-J1`…`J6`, `NET-K2`/`K3`/`K4` | all pass; only `llm-standin:8443` ever permitted (80 logged decisions) |
| 4 | Proxy bypass and abuse | `NET-H1` (api no direct egress), `NET-G3` (worker↛proxy), `NET-I3` (frontend↛proxy), `NET-J7*`/`J8`/`J9*` (proxy↛internal) | all pass |
| 5 | Verify attachments, identities, digests, routes, env, ports, socket; api edge binding **from the worker** | `NET-A/B/C/D/E/F*`, `NET-G5` | all pass |

## 2. Results — 91/91 probes

```
net_passed = true            probes = 91            failing = 0
ip_forward = 1               host LAN ip = 192.168.100.249
llm_test_configuration = {provider_host: llm-standin, provider_port: 8443,
                          real_provider_contacted: false}
```

| Group | Probes | Result |
|---|---|---|
| `NET-A:*` attachment sets (exact) | 7 | PASS |
| `NET-B:*` digest pinned + running digest matches | 14 | PASS |
| `NET-C:*` environment hygiene | 5 | PASS |
| `NET-D:*` no `0.0.0.0` publish | 7 | PASS |
| `NET-E:*` Docker socket absent | 7 | PASS |
| `NET-F:*` default route (only the proxy) | 6 | PASS |
| `NET-HG:*` host gateway vs LAN | 6 | PASS |
| `NET-G*` worker airgap | 8 | PASS |
| `NET-H*` api egress | 5 | PASS |
| `NET-I*` frontend | 5 | PASS |
| `NET-J*` proxy ACL, bypass, abuse | 17 | PASS |
| `NET-K*` ip_forward + non-contact | 4 | PASS |

Test suites, final run in one pass: `pytest tests/net` **19 passed** · `pytest tests/lab`
**60 passed** (including two new reset-regression tests) · `pytest backend/tests/invariants`
**11 passed, 13 milestone-aware skips preserved** · `lab_isolation_check.sh` **39/39, exit 0** ·
`net_verify.sh` **91/91, exit 0**, and **still exit 0 after the lab suite ran `lab-reset`**.

Proxy decision log (final run): 60 decisions — 12 allow, 12 close, **36 deny**
(24 `destination_not_allowlisted`, 12 `method_not_connect`). The only destination ever permitted was
`llm-standin:8443` (`docs/evidence/m1_5/proxy-decision-summary.txt`).

## 3. Induced failure and recovery (evidence: `docs/evidence/m1_5/`)

Attaching `vapt_worker` to `vapt_wan` — the exact failure the architecture exists to prevent:

```
PHASE 1  baseline      net_passed=true
PHASE 2  docker network connect vapt_wan vapt_worker   (worker default route: eth1)
PHASE 3  induced       net_passed=false, 8 probes failing
           NET-A:worker          required=vapt_core      observed=vapt_core,vapt_wan
           NET-F:worker          required=NONE           observed=PRESENT:eth1
           NET-G1                required=ENETUNREACH    observed=REACHABLE   <- internet
           NET-G2                required=ENETUNREACH    observed=REACHABLE   <- LAN gateway
           NET-G3                required=ENETUNREACH    observed=TimeoutError
           NET-G4                required=ENETUNREACH    observed=TimeoutError
           NET-G7                required=ENETUNREACH    observed=REACHABLE
           NET-HG:worker:lan-ip  required=ENETUNREACH    observed=ECONNREFUSED
PHASE 4  docker network disconnect                      (worker default route: none)
PHASE 5  reverted      net_passed=true
VERDICT  PROVEN
```

## 4. Topology as measured

```
vapt_edge    internal  172.30.20.0/24   frontend .10   api .20   <- api HTTP listener binds HERE ONLY
vapt_core    internal  172.30.21.0/24   api .20   worker .30   postgres .40   redis .50
vapt_egress  internal  172.30.22.0/24   api .20   egress-proxy .60
vapt_wan     bridge    172.30.23.0/24   egress-proxy .60   llm-standin .70   <- ONLY WAN route
vapt_lab     internal  172.30.10.0/24   zap .10   juiceshop .20   (+ worker from M3)
```

This **retires the `enable_ip_masquerade=false` proposal and its M2 risk item**: the api is on
internal networks only and therefore has no internet route at all, measured rather than assumed.

## 5. Corrections to my own expectations (found by running the check)

| Finding | Resolution |
|---|---|
| `NET-J7*`/`NET-J9*` expected `ENETUNREACH`, observed timeouts. The proxy **must** have a default route, so its packets to internal subnets leave via the host (which has routes to those bridges, `ip_forward=1`) and are **silently dropped by Docker's inter-network isolation** | probes now accept `ENETUNREACH \| TIMEOUT` and state the mechanism; recorded as assumption **B11** and limitation 25. Every other component has no default route at all — the stronger property |
| `NET-K3` originally asserted that provider hostnames must **not resolve** from the proxy. That is the wrong control: the proxy legitimately has a resolver, and resolution is not contact. The assertion would only have passed if DNS were broken — a meaningless pass | replaced with two real assertions: the decision log contains **no permitted tunnel** to any destination other than the stand-in, and **every** permitted tunnel resolved to `172.30.23.70` |
| `TimeoutError` vs `TIMEOUT` classification, YAML flow-mapping parse failure, missing `blocked()` helper | fixed; `bash -n` and `compose config -q` are part of the loop |
| **Both compose files declared `name: vapt`.** `make lab-reset` runs `down -v --remove-orphans`, which removes containers belonging to the project but absent from the given file — so resetting the lab **deleted the entire application plane**. Found by running the lab and net suites in one pass; the existing reset-scoping test did not catch it because it only guarded *unrelated* (non-VAPT) resources | the lab is now its own compose project (`vapt-lab`); `PUB-1` matches container names rather than the project label; two regression tests added — `test_compose_stacks_use_distinct_project_names` and `test_lab_reset_does_not_remove_the_application_plane` — and the full-pass re-run confirms `net_verify` still passes after `lab-reset` |

## 5a. Boundary verification (`docs/evidence/m1_5/boundary-verification.txt`)

Asked of the ZAP daemon itself after every suite: `active scans []`, `spider scans []`, `alerts 0`,
`sites []`, `messages 0`. Flags `SCANNER_EXECUTION_ENABLED`, `ZAP_ADAPTER_ENABLED`,
`ACTIVE_SCAN_ENABLED`, `DUAL_CONTROL_AVAILABLE` all `false`; adapter `mock`. Proxy log shows the only
permitted destination was the local stand-in. `lab/authorisation/MOCK-WEB-001.md` byte-identical to
commit `83497ce`, still carrying its `UNSIGNED DRAFT` marker. `scope_grant: null`. `docs/evidence/m1/`
unchanged since `9c988ba`. No application endpoint, migration, authentication, adapter or discovery
code exists.

## 6. Limitations

1. **Placeholders, not services.** Topology is proven; application behaviour is not. `postgres` and
   `redis` are listeners, not databases. M2 swaps in the real digest-pinned images on these networks.
2. The proxy is a small purpose-built CONNECT relay (≈150 lines, auditable). It is **not** a hardened
   general proxy; M6 may substitute Squid if a reason appears. Its ACL surface is deliberately tiny.
3. The stand-in is plain TCP, not TLS. The proxy only tunnels, so `CONNECT` semantics are identical;
   no TLS behaviour is claimed to be tested.
4. `vapt_wan` has real internet access **by design** (the proxy is the boundary). The proxy's ACL,
   not the network, is what prevents arbitrary destinations.
5. B11: the proxy's internal-subnet unreachability rests on Docker isolation rules (§5, row 1).
6. `ip_forward=1` on this host; recorded, not relied upon.
7. The worker joins `vapt_lab` in M3; M1.5 measured it on `vapt_core` only.

**Failed tests at completion: none.**
