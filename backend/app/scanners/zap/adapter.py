"""OWASP ZAP adapter.

Per-job isolation is IMPLEMENTED, not assumed (ADR-0008 R2/R3). The worker holds
the global daemon lease around this entire lifecycle, because `newSession` and
the sites/message/alert stores are daemon-global:

    newSession -> assert stores empty -> create context job-<id>
    -> include/exclude regexes -> budgets -> spider -> passive drain
    -> collect (baseurl-filtered, cross-checked) -> teardown -> assert empty

Active scanning is NOT implemented here: `active_scan` profiles are refused by
the adapter as well as by gate 7, so enabling a flag cannot reach an active scan
through this code path.
"""
from __future__ import annotations
import os
import re
import time
from ..base import (CancelResult, Capabilities, RawObservation, RawObservationBatch,
                    ScanJobSpec, ScannerHandle, ScannerProgress, ScannerError, ScopeRefused)
from .client import ZapApiError, ZapClient


def _context_name(job_id: str) -> str:
    return f"job-{job_id}"


class ZapAdapter:
    name = "zap"

    def __init__(self, client: ZapClient | None = None) -> None:
        self._client = client or ZapClient()
        self._idle_timeout = int(os.environ.get("ZAP_TEARDOWN_IDLE_TIMEOUT_SECONDS", "60"))
        self._idle_poll = int(os.environ.get("ZAP_TEARDOWN_IDLE_POLL_SECONDS", "2"))

    # ------------------------------------------------------------ contract --
    def capabilities(self) -> Capabilities:
        return Capabilities(name="zap", version=self.version(), supports_passive=True,
                            supports_active=False,      # deliberately not implemented
                            supports_spider=True, supports_pause=False, supports_cancel=True,
                            emits_request_response=True, requires_exclusive_daemon=True)

    def version(self) -> str:
        try:
            return self._client.version()
        except ZapApiError:
            return "unreachable"

    def preflight(self, spec: ScanJobSpec) -> None:
        if not spec.scope_decision_allowed:
            raise ScopeRefused("refusing to start: the job does not carry an allow ScopeDecision")
        if not spec.pinned_ips:
            raise ScopeRefused("refusing to start: no pinned target address")
        if spec.profile.active_scan or spec.profile.is_intrusive:
            raise ScopeRefused("this adapter does not implement active or intrusive scanning")
        version = self._client.version()
        if not version:
            raise ScannerError("ZAP did not report a version")

    # ------------------------------------------------------- session set-up --
    def begin_session(self, spec: ScanJobSpec) -> str:
        """newSession + assert stores empty. Returns the asserted detail string."""
        self._client.new_session(f"job-{spec.job_id}")
        empty, detail = self._client.stores_empty()
        if not empty:
            raise ScannerError(f"stores not empty after newSession: {detail}")
        return detail

    def start(self, spec: ScanJobSpec) -> ScannerHandle:
        self.preflight(spec)
        ctx = _context_name(spec.job_id)
        self._client.new_context(ctx)
        host = re.escape(f"{spec.asset.protocol}://{spec.asset.hostname}:{spec.asset.port}")
        for prefix in (spec.included_path_prefixes or ("/",)):
            self._client.include_in_context(ctx, f"{host}{re.escape(prefix)}.*")
        for prefix in spec.excluded_path_prefixes:
            self._client.exclude_from_context(ctx, f"{host}{re.escape(prefix)}.*")
        # Budgets, applied before anything is requested.
        try:
            self._client.set_option("/JSON/spider/action/setOptionMaxDepth/",
                                    Integer=spec.profile.spider_max_depth)
            self._client.set_option("/JSON/spider/action/setOptionMaxChildren/",
                                    Integer=spec.profile.spider_max_children)
            delay_ms = int(1000 / max(spec.profile.max_requests_per_second, 1))
            self._client.set_option("/JSON/spider/action/setOptionRequestWaitTime/",
                                    Integer=delay_ms)
            self._client.set_option("/JSON/spider/action/setOptionThreadCount/", Integer=1)
        except ZapApiError as exc:
            raise ScannerError(f"could not apply budgets: {exc}") from exc
        base = f"{spec.asset.protocol}://{spec.asset.hostname}:{spec.asset.port}{spec.asset.base_path or '/'}"
        scan_id = self._client.spider_scan(base, ctx, spec.profile.spider_max_children)
        return ScannerHandle(job_id=spec.job_id,
                             external_ids={"context": ctx, "scan": scan_id, "baseurl": base})

    def poll(self, handle: ScannerHandle) -> ScannerProgress:
        scan_id = handle.external_ids.get("scan", "")
        base = handle.external_ids.get("baseurl")
        try:
            spider_pct = self._client.spider_status(scan_id) if scan_id else 100
            pending = self._client.passive_records_to_scan()
            alerts = self._client.number_of_alerts(base)
            messages = self._client.number_of_messages()
        except ZapApiError as exc:
            raise ScannerError(f"poll failed: {exc}") from exc
        running = spider_pct < 100 or pending > 0
        phase = "spider" if spider_pct < 100 else ("passive" if pending > 0 else "collect")
        pct = int((spider_pct * 0.7) + (30 if pending == 0 else 0))
        return ScannerProgress(phase=phase, percent=pct, requests_made=messages,
                               alerts_seen=alerts, is_running=running,
                               messages=(f"spider={spider_pct}% passive_queue={pending}",))

    def cancel(self, handle: ScannerHandle) -> CancelResult:
        try:
            self._client.spider_stop_all()
            self._client.stop_all_active()
        except ZapApiError as exc:
            return CancelResult(False, f"stop call failed: {exc}")
        deadline = time.monotonic() + self._idle_timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                idle, last = self._client.is_idle()
            except ZapApiError as exc:
                return CancelResult(False, f"idle check failed: {exc}")
            if idle:
                return CancelResult(True, f"confirmed idle ({last})")
            time.sleep(self._idle_poll)
        return CancelResult(False, f"not confirmed idle within {self._idle_timeout}s ({last})")

    def collect(self, handle: ScannerHandle, cursor: str | None) -> RawObservationBatch:
        base = handle.external_ids.get("baseurl")
        start = int(cursor or 0)
        try:
            alerts = self._client.alerts(baseurl=base, start=start, count=100)
        except ZapApiError as exc:
            raise ScannerError(f"collect failed: {exc}") from exc
        items: list[RawObservation] = []
        for alert in alerts:
            req = resp = None
            mid = str(alert.get("messageId") or "")
            if mid:
                try:
                    msg = self._client.message(mid)
                    req = (msg.get("requestHeader", "") + msg.get("requestBody", "")) or None
                    resp = (msg.get("responseHeader", "") + msg.get("responseBody", "")) or None
                except ZapApiError:
                    pass
            items.append(RawObservation(adapter_rule_id=str(alert.get("pluginId") or ""),
                                        payload=dict(alert), observed_url=alert.get("url"),
                                        request_text=req, response_text=resp))
        next_cursor = str(start + len(alerts)) if len(alerts) == 100 else None
        return RawObservationBatch(cursor=next_cursor, items=tuple(items))

    def teardown(self, handle: ScannerHandle) -> CancelResult:
        """stopScan -> confirm idle -> removeContext -> newSession -> assert empty.
        ANY failure here marks the daemon dirty (the caller's responsibility)."""
        steps: list[str] = []
        cancelled = self.cancel(handle)
        steps.append(f"stop/idle: {cancelled.detail}")
        if not cancelled.confirmed_stopped:
            return CancelResult(False, "; ".join(steps))
        ctx = handle.external_ids.get("context")
        try:
            if ctx and ctx in self._client.contexts():
                self._client.remove_context(ctx)
            steps.append("context removed")
            self._client.new_session(f"post-{handle.job_id}")
            steps.append("session discarded")
            empty, detail = self._client.stores_empty()
            steps.append(f"stores: {detail}")
            if not empty:
                return CancelResult(False, "; ".join(steps))
        except ZapApiError as exc:
            steps.append(f"teardown call failed: {exc}")
            return CancelResult(False, "; ".join(steps))
        return CancelResult(True, "; ".join(steps))
