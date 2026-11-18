"""Mock adapter — the DEFAULT. Replays hand-authored ZAP-shaped fixtures.

It makes no network connection of any kind, so the whole pipeline (job
lifecycle, raw observation capture, ingestion rejection, teardown, cancellation)
runs in CI without ZAP or a target. Fault injection is supported through the
profile key suffix so the failure paths are testable:

    <profile>              normal run
    MOCK_FAULT=slow        progress reported over several polls
    MOCK_FAULT=no_stop     cancel() reports NOT confirmed -> job fails, daemon dirty
    MOCK_FAULT=dirty       teardown() reports NOT confirmed -> daemon dirty
    MOCK_FAULT=malformed   one observation has an unparseable payload
"""
from __future__ import annotations
import json
import os
import pathlib
from ..base import (CancelResult, Capabilities, RawObservation, RawObservationBatch,
                    ScanJobSpec, ScannerHandle, ScannerProgress, ScopeRefused)

FIXTURE = pathlib.Path("/srv/fixtures/zap/passive-baseline.json")


class MockAdapter:
    name = "mock"

    def __init__(self) -> None:
        self._fault = os.environ.get("MOCK_FAULT", "")
        self._polls: dict[str, int] = {}

    def capabilities(self) -> Capabilities:
        return Capabilities(name="mock", version="0.4.0", supports_passive=True,
                            supports_active=False, supports_spider=True, supports_pause=False,
                            supports_cancel=True, emits_request_response=True,
                            requires_exclusive_daemon=False)

    def preflight(self, spec: ScanJobSpec) -> None:
        if not spec.scope_decision_allowed:
            raise ScopeRefused("refusing to start: the job does not carry an allow ScopeDecision")
        # Fixture work makes no network contact, so it must NOT require a
        # resolvable target: requiring one would couple the fixture path to the
        # lab being up, which is exactly what fixture mode exists to avoid.
        if spec.mode == "live" and not spec.pinned_ips:
            raise ScopeRefused("refusing to start live work: no pinned target address")

    def start(self, spec: ScanJobSpec) -> ScannerHandle:
        self.preflight(spec)
        self._polls[spec.job_id] = 0
        return ScannerHandle(job_id=spec.job_id,
                             external_ids={"session": f"mock-{spec.job_id}", "scan": "0"})

    def poll(self, handle: ScannerHandle) -> ScannerProgress:
        n = self._polls.get(handle.job_id, 0) + 1
        self._polls[handle.job_id] = n
        total = 3 if self._fault == "slow" else 1
        running = n < total
        pct = int(min(100, n / total * 100))
        return ScannerProgress(phase="passive" if running else "collect", percent=pct,
                               requests_made=n * 4, alerts_seen=0 if running else 7,
                               is_running=running, messages=(f"mock poll {n}/{total}",))

    def cancel(self, handle: ScannerHandle) -> CancelResult:
        if self._fault == "no_stop":
            return CancelResult(False, "mock fault: scanner did not confirm it stopped")
        return CancelResult(True, "mock scanner confirmed idle")

    def collect(self, handle: ScannerHandle, cursor: str | None) -> RawObservationBatch:
        doc = json.loads(FIXTURE.read_text())
        messages = doc.get("messages", {})
        items: list[RawObservation] = []
        for alert in doc["alerts"]:
            msg = messages.get(str(alert.get("messageId", "")), {})
            payload = dict(alert)
            if self._fault == "malformed" and alert.get("messageId") == "21":
                payload = {"unparseable": True, "pluginId": None}
            items.append(RawObservation(
                adapter_rule_id=str(alert.get("pluginId") or ""), payload=payload,
                observed_url=alert.get("url"),
                request_text=(msg.get("requestHeader", "") + msg.get("requestBody", "")) or None,
                response_text=(msg.get("responseHeader", "") + msg.get("responseBody", "")) or None))
        return RawObservationBatch(cursor=None, items=tuple(items))

    def teardown(self, handle: ScannerHandle) -> CancelResult:
        self._polls.pop(handle.job_id, None)
        if self._fault == "dirty":
            return CancelResult(False, "mock fault: stores not empty after teardown")
        return CancelResult(True, "mock session discarded; stores empty")
