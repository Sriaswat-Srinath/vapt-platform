"""The scanner adapter contract.

Rules every adapter must honour (docs/SCANNER_INTEGRATION.md):
  * `start()` refuses any spec not carrying an ALLOW decision — the adapter
    re-checks rather than trusting its caller.
  * Adapters NEVER write findings. They return verbatim raw observations;
    normalisation is a separate pure step, so historical scans can be
    re-normalised with an improved mapper.
  * `cancel()` returns whether the scanner is CONFIRMED stopped. Unconfirmed
    cancellation fails the job and marks the daemon dirty.
  * `requires_exclusive_daemon` declares whether the adapter shares global
    daemon state and therefore needs the global lease.
"""
from __future__ import annotations
import dataclasses as dc
import hashlib
import json
from typing import Protocol, runtime_checkable


@dc.dataclass(frozen=True, slots=True)
class Capabilities:
    name: str
    version: str
    supports_passive: bool
    supports_active: bool
    supports_spider: bool
    supports_pause: bool
    supports_cancel: bool
    emits_request_response: bool
    requires_exclusive_daemon: bool


@dc.dataclass(frozen=True, slots=True)
class AssetSnapshot:
    asset_id: str
    asset_identifier: str
    hostname: str
    protocol: str
    port: int
    base_path: str


@dc.dataclass(frozen=True, slots=True)
class ProfileSnapshot:
    key: str
    adapter_name: str
    is_intrusive: bool
    active_scan: bool
    max_requests_per_second: int
    max_total_requests: int
    max_duration_seconds: int
    spider_max_depth: int
    spider_max_children: int
    excluded_path_patterns: tuple[str, ...]
    method_denylist: tuple[str, ...]
    excluded_rule_ids: tuple[str, ...]


@dc.dataclass(frozen=True, slots=True)
class ScanJobSpec:
    """Built ONLY from a persisted allow ScopeDecision."""
    job_id: str
    asset: AssetSnapshot
    profile: ProfileSnapshot
    pinned_ips: tuple[str, ...]
    seed_paths: tuple[str, ...]
    included_path_prefixes: tuple[str, ...]
    excluded_path_prefixes: tuple[str, ...]
    scope_decision_allowed: bool
    scope_decision_id: str | None


@dc.dataclass(frozen=True, slots=True)
class ScannerHandle:
    job_id: str
    external_ids: dict[str, str]


@dc.dataclass(frozen=True, slots=True)
class ScannerProgress:
    phase: str
    percent: int | None
    requests_made: int
    alerts_seen: int
    is_running: bool
    messages: tuple[str, ...] = ()


@dc.dataclass(frozen=True, slots=True)
class RawObservation:
    adapter_rule_id: str | None
    payload: dict
    observed_url: str | None
    request_text: str | None = None
    response_text: str | None = None

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.payload, sort_keys=True, separators=(",", ":"),
                       default=str).encode()).hexdigest()

    def _h(self, text: str | None) -> str | None:
        return hashlib.sha256(text.encode()).hexdigest() if text is not None else None

    @property
    def request_sha256(self) -> str | None:
        return self._h(self.request_text)

    @property
    def response_sha256(self) -> str | None:
        return self._h(self.response_text)


@dc.dataclass(frozen=True, slots=True)
class RawObservationBatch:
    cursor: str | None
    items: tuple[RawObservation, ...]


@dc.dataclass(frozen=True, slots=True)
class CancelResult:
    confirmed_stopped: bool
    detail: str


class ScannerError(Exception):
    """Adapter-level failure. The worker turns this into a failed job."""


class ScopeRefused(ScannerError):
    """The adapter refused a spec that did not carry an allow decision."""


@runtime_checkable
class ScannerAdapter(Protocol):
    def capabilities(self) -> Capabilities: ...
    def preflight(self, spec: ScanJobSpec) -> None: ...
    def start(self, spec: ScanJobSpec) -> ScannerHandle: ...
    def poll(self, handle: ScannerHandle) -> ScannerProgress: ...
    def cancel(self, handle: ScannerHandle) -> CancelResult: ...
    def collect(self, handle: ScannerHandle, cursor: str | None) -> RawObservationBatch: ...
    def teardown(self, handle: ScannerHandle) -> CancelResult: ...
