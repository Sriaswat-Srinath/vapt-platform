"""The preflight gate chain — deterministic, pure, total.

This module performs NO I/O and imports nothing from the API, the agent or any
repository. It is a pure function of an immutable snapshot:

    evaluate(ScopeRequest) -> ScopeDecisionResult

Properties the rest of the system relies on (docs/SAFETY.md §2, §7.1):
  * total      — every input produces a decision; an exception inside a gate is
                 caught and becomes a DENY, never an implicit allow
  * ordered    — gates run in order and short-circuit on the first denial
  * explainable— every gate records pass/fail and a reason; the full ordered
                 list is persisted and returned to the caller (HTTP 409)
  * versioned  — POLICY_VERSION is stored on every decision

The LLM cannot reach this module, and nothing here consults it.
"""
from __future__ import annotations
import dataclasses as dc
import datetime as dt
import ipaddress
from typing import Callable

POLICY_VERSION = "1.1.0"   # 1.1.0: gate 2 requires host hygiene as well as containment (ADR-0015)


@dc.dataclass(frozen=True, slots=True)
class GrantSnapshot:
    id: str
    state: str
    document_state: str
    allowed_cidrs: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    allowed_profiles: tuple[str, ...]
    intrusive_allowed: bool
    valid_from: dt.datetime | None
    valid_until: dt.datetime | None
    revoked_at: dt.datetime | None


@dc.dataclass(frozen=True, slots=True)
class ProfileSnapshot:
    key: str
    adapter_name: str
    is_intrusive: bool
    active_scan: bool
    method_denylist: tuple[str, ...] = ()
    excluded_path_patterns: tuple[str, ...] = ()


@dc.dataclass(frozen=True, slots=True)
class ScopeRuleSnapshot:
    kind: str                      # include | exclude
    host_pattern: str
    port: int | None
    path_prefix: str
    method_allowlist: tuple[str, ...] = ()


@dc.dataclass(frozen=True, slots=True)
class ApprovalSnapshot:
    id: str
    kind: str
    state: str
    requested_by: str
    decided_by: str | None
    expires_at: dt.datetime | None
    requester_identity_ok: bool     # attested, distinct, active
    decider_identity_ok: bool


# Execution modes. `fixture` work replays recorded/hand-authored data and makes
# NO network contact of any kind, so the execution-specific gates do not apply to
# it — exactly as for fixture discovery. It is a distinct mode recorded on every
# decision, NOT a relaxation of a gate: a fixture decision can never authorise a
# scan, because `live` is the only mode an adapter that touches the target accepts.
MODE_FIXTURE = "fixture"
MODE_LIVE = "live"
EXECUTION_GATES = ("scanner_execution_enabled", "lab_isolation_valid", "grant_active",
                   "profile_allowed", "intrusive_approval", "target_resolution",
                   "port_allowed", "scanner_daemon_available")
NOT_APPLICABLE = "not applicable in fixture mode: no network contact is made"


@dc.dataclass(frozen=True, slots=True)
class ScopeRequest:
    """Immutable snapshot of everything the decision depends on."""
    now: dt.datetime
    subject_type: str
    mode: str = MODE_LIVE
    target_url_path: str = "/"
    target_method: str = "GET"

    # global flags
    scanner_execution_enabled: bool = False
    active_scan_enabled: bool = False
    dual_control_available_flag: bool = False
    attested_distinct_active_identities: int = 0
    dual_control_min_identities: int = 2

    # isolation. TWO verdicts, deliberately not merged (ADR-0015):
    #   isolation_passed     containment — container->internet and container->LAN blocked
    #   host_hygiene_passed  no foreign 0.0.0.0 host listener reachable from the lab
    # Gate 2 requires BOTH for live execution. They stay separate so a report can
    # say which one failed, and so the recovery path can require containment only.
    isolation_passed: bool | None = None
    host_hygiene_passed: bool | None = None
    host_wildcard_listeners: str | None = None
    isolation_valid_until: dt.datetime | None = None

    # asset
    asset_exists: bool = False
    asset_state: str | None = None
    asset_environment: str | None = None
    asset_hostname: str | None = None
    asset_port: int | None = None

    # grant / profile / approval
    grant: GrantSnapshot | None = None
    profile: ProfileSnapshot | None = None
    approval: ApprovalSnapshot | None = None

    # resolution (performed by the caller; resolve-once-and-pin, ADR-0006)
    resolved_ips: tuple[str, ...] = ()
    resolution_error: str | None = None

    # rules and budgets
    scope_rules: tuple[ScopeRuleSnapshot, ...] = ()
    in_flight_jobs_global: int = 0
    in_flight_jobs_for_asset: int = 0
    max_concurrent_jobs_global: int = 2
    max_concurrent_jobs_per_asset: int = 1

    # scanner daemon
    adapter_requires_exclusive_daemon: bool = False
    daemon_dirty: bool = False
    daemon_lease_held: bool = False


@dc.dataclass(frozen=True, slots=True)
class GateResult:
    gate: str
    passed: bool
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {"gate": self.gate, "pass": self.passed}
        if self.reason:
            d["reason"] = self.reason
        return d


@dc.dataclass(frozen=True, slots=True)
class ScopeDecisionResult:
    decision: str                      # allow | deny
    policy_version: str
    gate_results: tuple[GateResult, ...]
    resolved_ips: tuple[str, ...] = ()
    mode: str = MODE_LIVE

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def first_failure(self) -> GateResult | None:
        return next((g for g in self.gate_results if not g.passed), None)

    def as_dict(self) -> dict[str, object]:
        return {
            "policy_version": self.policy_version,
            "decision": self.decision,
            "mode": self.mode,
            "gate_results": [g.as_dict() for g in self.gate_results],
            "resolved_ips": list(self.resolved_ips),
        }


# ------------------------------------------------------------------ gates ----
def _g1(r: ScopeRequest) -> GateResult:
    return GateResult("scanner_execution_enabled", r.scanner_execution_enabled,
                      None if r.scanner_execution_enabled else
                      "SCANNER_EXECUTION_ENABLED is false; scanner execution is disabled")


def _g2(r: ScopeRequest) -> GateResult:
    """Containment AND host hygiene, both required (ADR-0015).

    Containment is the control: the scanner cannot reach the internet or the
    LAN. Host hygiene is the environment: no foreign wildcard listener on the
    host is reachable from the lab through its gateway. A scanner that can
    reach an unrelated service on the operator's machine is out of scope even
    though it never left the host, so both must hold before anything executes.

    They are reported separately so a denial names which one failed, and so a
    recovery path can require containment alone.
    """
    if r.isolation_passed is None:
        return GateResult("lab_isolation_valid", False,
                          "no lab isolation check has been reported; run `make lab-check` and report it")
    if not r.isolation_passed:
        return GateResult("lab_isolation_valid", False, "the latest lab isolation check did not pass")
    if r.host_hygiene_passed is None:
        return GateResult("lab_isolation_valid", False,
                          "the reported isolation check predates host-hygiene reporting; re-run "
                          "`make lab-check` and report it before executing anything")
    if not r.host_hygiene_passed:
        listeners = (r.host_wildcard_listeners or "").strip()
        detail = f" ({listeners})" if listeners else ""
        return GateResult("lab_isolation_valid", False,
                          "host hygiene failed: a wildcard host listener is reachable from the "
                          f"lab through its gateway{detail}. Containment passed, so the scanner "
                          "cannot reach the internet or the LAN, but it could reach that service. "
                          "Resolve the listener or bind it to loopback; do not weaken this gate.")
    if r.isolation_valid_until is None or r.isolation_valid_until <= r.now:
        return GateResult("lab_isolation_valid", False,
                          f"the lab isolation check is stale (valid_until={r.isolation_valid_until})")
    return GateResult("lab_isolation_valid", True)


def _g3(r: ScopeRequest) -> GateResult:
    if not r.asset_exists:
        return GateResult("asset_registered", False, "asset is not registered")
    if r.asset_state == "archived":
        return GateResult("asset_registered", False, "asset is archived")
    return GateResult("asset_registered", True)


def _g4(r: ScopeRequest) -> GateResult:
    ok = r.asset_environment == "mock_lab"
    return GateResult("environment_is_mock", ok, None if ok else
                      f"asset environment {r.asset_environment!r} is not 'mock_lab'")


def _g5(r: ScopeRequest) -> GateResult:
    g = r.grant
    if g is None:
        return GateResult("grant_active", False, "no scope grant exists for this asset")
    if g.state != "active":
        return GateResult("grant_active", False, f"scope grant state is {g.state!r}, not 'active'")
    if g.document_state != "signed_verified":
        return GateResult("grant_active", False,
                          f"authorisation document state is {g.document_state!r}; "
                          "it must be signed and verified")
    if g.revoked_at is not None:
        return GateResult("grant_active", False, "scope grant has been revoked")
    if g.valid_from is not None and r.now < g.valid_from:
        return GateResult("grant_active", False, "scope grant is not yet valid")
    if g.valid_until is not None and r.now >= g.valid_until:
        return GateResult("grant_active", False, "scope grant has expired")
    return GateResult("grant_active", True)


def _g6(r: ScopeRequest) -> GateResult:
    if r.profile is None:
        return GateResult("profile_allowed", False, "no scan profile was selected")
    assert r.grant is not None
    if r.profile.key not in r.grant.allowed_profiles:
        return GateResult("profile_allowed", False,
                          f"profile {r.profile.key!r} is not in the grant's allowed profiles "
                          f"{list(r.grant.allowed_profiles)}")
    return GateResult("profile_allowed", True)


def _g7(r: ScopeRequest) -> GateResult:
    """Intrusive/active work needs genuine dual control. No config bypasses this."""
    p, g = r.profile, r.grant
    assert p is not None and g is not None
    if not (p.is_intrusive or p.active_scan):
        return GateResult("intrusive_approval", True)
    # Effective dual control is COMPUTED, never read from the flag alone.
    effective_dual_control = (r.dual_control_available_flag and
                              r.attested_distinct_active_identities >= r.dual_control_min_identities)
    if not r.active_scan_enabled:
        return GateResult("intrusive_approval", False,
                          "ACTIVE_SCAN_ENABLED is false; intrusive profiles are disabled")
    if not effective_dual_control:
        return GateResult("intrusive_approval", False,
                          "genuine dual control is unavailable "
                          f"({r.attested_distinct_active_identities} attested distinct active "
                          f"identities, {r.dual_control_min_identities} required); "
                          "intrusive profiles remain disabled")
    if not g.intrusive_allowed:
        return GateResult("intrusive_approval", False, "the scope grant does not allow intrusive testing")
    a = r.approval
    if a is None or a.kind != "intrusive_profile" or a.state != "approved":
        return GateResult("intrusive_approval", False, "no approved intrusive_profile approval")
    if a.expires_at is not None and a.expires_at <= r.now:
        return GateResult("intrusive_approval", False, "the intrusive approval has expired")
    if a.decided_by is None or a.decided_by == a.requested_by:
        return GateResult("intrusive_approval", False,
                          "the approval was not decided by a second party")
    if not (a.requester_identity_ok and a.decider_identity_ok):
        return GateResult("intrusive_approval", False,
                          "an approval party is no longer an attested, distinct, active identity")
    return GateResult("intrusive_approval", True)


def _g8(r: ScopeRequest) -> GateResult:
    """Resolve once; every returned address must be in the grant's CIDRs."""
    assert r.grant is not None
    if r.resolution_error:
        return GateResult("target_resolution", False, f"resolution failed: {r.resolution_error}")
    if not r.resolved_ips:
        return GateResult("target_resolution", False,
                          f"{r.asset_hostname} resolved to no addresses")
    try:
        nets = [ipaddress.ip_network(c) for c in r.grant.allowed_cidrs]
    except ValueError as exc:
        return GateResult("target_resolution", False, f"malformed allowed_cidrs: {exc}")
    outside = []
    for ip in r.resolved_ips:
        addr = ipaddress.ip_address(ip)
        if not any(addr in n for n in nets):
            outside.append(ip)
    if outside:
        return GateResult("target_resolution", False,
                          f"{r.asset_hostname} resolved to {outside}, outside allowed_cidrs "
                          f"{list(r.grant.allowed_cidrs)}")
    return GateResult("target_resolution", True)


def _g9(r: ScopeRequest) -> GateResult:
    assert r.grant is not None
    if r.asset_port not in r.grant.allowed_ports:
        return GateResult("port_allowed", False,
                          f"port {r.asset_port} is not in allowed_ports {list(r.grant.allowed_ports)}")
    return GateResult("port_allowed", True)


def _path_matches(prefix: str, path: str) -> bool:
    return path == prefix or path.startswith(prefix if prefix.endswith("/") else prefix + "/") \
        or (prefix == "/" and path.startswith("/"))


def _g10(r: ScopeRequest) -> GateResult:
    host, port, path = r.asset_hostname, r.asset_port, r.target_url_path
    method = r.target_method.upper()
    includes = [x for x in r.scope_rules if x.kind == "include"]
    excludes = [x for x in r.scope_rules if x.kind == "exclude"]
    if r.profile and method in {m.upper() for m in r.profile.method_denylist}:
        return GateResult("scope_rules", False, f"method {method} is in the profile's method denylist")
    matched = [x for x in includes
               if x.host_pattern == host and (x.port in (None, port)) and _path_matches(x.path_prefix, path)]
    if not matched:
        return GateResult("scope_rules", False,
                          f"{host}:{port}{path} does not match any include rule")
    for x in excludes:
        if x.host_pattern == host and (x.port in (None, port)) and _path_matches(x.path_prefix, path):
            return GateResult("scope_rules", False,
                              f"{path} matches exclude rule {x.path_prefix!r} (exclude always wins)")
    allowed_methods = {m.upper() for x in matched for m in x.method_allowlist}
    if allowed_methods and method not in allowed_methods:
        return GateResult("scope_rules", False,
                          f"method {method} is not in the include rule's allowlist {sorted(allowed_methods)}")
    return GateResult("scope_rules", True)


def _g11(r: ScopeRequest) -> GateResult:
    if r.in_flight_jobs_global >= r.max_concurrent_jobs_global:
        return GateResult("concurrency_budget", False,
                          f"{r.in_flight_jobs_global} jobs in flight; global limit is "
                          f"{r.max_concurrent_jobs_global}")
    return GateResult("concurrency_budget", True)


def _g12(r: ScopeRequest) -> GateResult:
    if r.in_flight_jobs_for_asset >= r.max_concurrent_jobs_per_asset:
        return GateResult("no_conflicting_job", False,
                          "another job is already in flight for this asset")
    return GateResult("no_conflicting_job", True)


def _g13(r: ScopeRequest) -> GateResult:
    if not r.adapter_requires_exclusive_daemon:
        return GateResult("scanner_daemon_available", True)
    if r.daemon_dirty:
        return GateResult("scanner_daemon_available", False,
                          "the scanner daemon is marked dirty; an audited admin reset is required")
    if r.daemon_lease_held:
        return GateResult("scanner_daemon_available", False,
                          "the exclusive scanner daemon lease is held by another job")
    return GateResult("scanner_daemon_available", True)


# (ordinal, name, implementation). The name is stable and is used even when a
# gate cannot be evaluated, so a dry run never shows an internal symbol.
GATES: tuple[tuple[int, str, Callable[[ScopeRequest], GateResult]], ...] = (
    (1, "scanner_execution_enabled", _g1),
    (2, "lab_isolation_valid", _g2),
    (3, "asset_registered", _g3),
    (4, "environment_is_mock", _g4),
    (5, "grant_active", _g5),
    (6, "profile_allowed", _g6),
    (7, "intrusive_approval", _g7),
    (8, "target_resolution", _g8),
    (9, "port_allowed", _g9),
    (10, "scope_rules", _g10),
    (11, "concurrency_budget", _g11),
    (12, "no_conflicting_job", _g12),
    (13, "scanner_daemon_available", _g13),
)
GATE_NAMES: tuple[str, ...] = tuple(name for _, name, _ in GATES)


def evaluate(request: ScopeRequest, *, short_circuit: bool = True) -> ScopeDecisionResult:
    """Ordered and total. Any exception becomes a DENY.

    `short_circuit=True` (the authoritative path) stops at the first denial.
    `short_circuit=False` evaluates every gate so a dry run can show the analyst
    the complete picture; the decision is identical — deny if any gate failed.
    Later gates may depend on earlier ones, so when a gate cannot be evaluated
    its result is recorded as a denial with `not_evaluated`.
    """
    results: list[GateResult] = []
    failed = False
    for _ordinal, name, gate in GATES:
        if request.mode == MODE_FIXTURE and name in EXECUTION_GATES:
            results.append(GateResult(name, True, NOT_APPLICABLE))
            continue
        try:
            res = gate(request)
        except Exception as exc:                      # noqa: BLE001 - deliberate
            res = (GateResult(name, False, "not_evaluated: an earlier gate denied")
                   if failed else
                   GateResult(name, False, f"gate raised {exc.__class__.__name__}: {exc}"))
        results.append(res)
        if not res.passed:
            failed = True
            if short_circuit:
                break
    decision = "deny" if failed else "allow"
    return ScopeDecisionResult(decision, POLICY_VERSION, tuple(results), request.resolved_ips,
                               request.mode)
