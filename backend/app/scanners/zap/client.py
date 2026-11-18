"""Minimal ZAP REST client.

Deliberately small and explicit: every call names the endpoint it uses, the API
key is always sent, and `trust_env=False` so target/control traffic never
consults a proxy variable.
"""
from __future__ import annotations
import os
import httpx


class ZapApiError(RuntimeError):
    pass


class ZapClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 timeout: int | None = None) -> None:
        # An EMPTY env var is a realistic misconfiguration (`-e VAR="$UNSET"`),
        # so fall back on blank as well as on absent, and fail loudly on a URL
        # with no scheme rather than emitting a confusing client error later.
        self.base_url = (base_url or os.environ.get("ZAP_BASE_URL") or
                         "http://172.30.10.10:8080").rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError(f"ZAP_BASE_URL must include a scheme, got {self.base_url!r}")
        self.api_key = api_key or os.environ.get("ZAP_API_KEY") or ""
        self.timeout = timeout or int(os.environ.get("ZAP_API_CALL_TIMEOUT_SECONDS") or "10")
        self._c = httpx.Client(timeout=self.timeout, trust_env=False, follow_redirects=False)

    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> "ZapClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def call(self, path: str, **params) -> dict:
        params["apikey"] = self.api_key
        try:
            r = self._c.get(f"{self.base_url}{path}", params=params)
        except httpx.HTTPError as exc:
            raise ZapApiError(f"{path}: {type(exc).__name__}: {exc}") from exc
        if r.status_code != 200:
            raise ZapApiError(f"{path}: HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except ValueError as exc:
            raise ZapApiError(f"{path}: non-JSON response") from exc

    # ---- control plane (touches ZAP only; never the target) ----------------
    def version(self) -> str:
        return str(self.call("/JSON/core/view/version/").get("version", ""))

    def new_session(self, name: str) -> None:
        self.call("/JSON/core/action/newSession/", name=name, overwrite="true")

    def alerts(self, baseurl: str | None = None, start: int = 0, count: int = 100) -> list[dict]:
        params = {"start": start, "count": count}
        if baseurl:
            params["baseurl"] = baseurl
        return list(self.call("/JSON/alert/view/alerts/", **params).get("alerts", []))

    def number_of_alerts(self, baseurl: str | None = None) -> int:
        params = {"baseurl": baseurl} if baseurl else {}
        return int(self.call("/JSON/core/view/numberOfAlerts/", **params).get("numberOfAlerts", 0))

    def sites(self) -> list[str]:
        return list(self.call("/JSON/core/view/sites/").get("sites", []))

    def number_of_messages(self) -> int:
        return int(self.call("/JSON/core/view/numberOfMessages/").get("numberOfMessages", 0))

    def message(self, message_id: str) -> dict:
        return dict(self.call("/JSON/core/view/message/", id=message_id).get("message", {}))

    def contexts(self) -> list[str]:
        return list(self.call("/JSON/context/view/contextList/").get("contextList", []))

    def new_context(self, name: str) -> str:
        return str(self.call("/JSON/context/action/newContext/", contextName=name).get("contextId", ""))

    def remove_context(self, name: str) -> None:
        self.call("/JSON/context/action/removeContext/", contextName=name)

    def include_in_context(self, name: str, regex: str) -> None:
        self.call("/JSON/context/action/includeInContext/", contextName=name, regex=regex)

    def exclude_from_context(self, name: str, regex: str) -> None:
        self.call("/JSON/context/action/excludeFromContext/", contextName=name, regex=regex)

    def set_option(self, path: str, **params) -> None:
        self.call(path, **params)

    # ---- data plane (only ever reaches the pinned, authorised target) ------
    def spider_scan(self, url: str, context_name: str, max_children: int) -> str:
        return str(self.call("/JSON/spider/action/scan/", url=url, contextName=context_name,
                             maxChildren=max_children, recurse="true").get("scan", ""))

    def spider_status(self, scan_id: str) -> int:
        return int(self.call("/JSON/spider/view/status/", scanId=scan_id).get("status", 0))

    def spider_stop_all(self) -> None:
        self.call("/JSON/spider/action/stopAllScans/")

    def passive_records_to_scan(self) -> int:
        return int(self.call("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0))

    def active_scans(self) -> list[dict]:
        return list(self.call("/JSON/ascan/view/scans/").get("scans", []))

    def spider_scans(self) -> list[dict]:
        return list(self.call("/JSON/spider/view/scans/").get("scans", []))

    def stop_all_active(self) -> None:
        self.call("/JSON/ascan/action/stopAllScans/")

    def is_idle(self) -> tuple[bool, str]:
        """Confirmed-idle check used by cancellation and teardown."""
        active = [s for s in self.active_scans() if str(s.get("state", "")).upper() == "RUNNING"]
        spiders = [s for s in self.spider_scans() if str(s.get("state", "")).upper() == "RUNNING"]
        pending = self.passive_records_to_scan()
        idle = not active and not spiders and pending == 0
        return idle, f"active={len(active)} spider={len(spiders)} passive_queue={pending}"

    def stores_empty(self) -> tuple[bool, str]:
        alerts, sites, messages = self.number_of_alerts(), self.sites(), self.number_of_messages()
        return (alerts == 0 and not sites and messages == 0,
                f"alerts={alerts} sites={len(sites)} messages={messages}")
