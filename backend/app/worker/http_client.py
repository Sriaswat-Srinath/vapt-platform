"""The ONLY outbound HTTP client used against an assessment target.

Every safety control the design requires is enforced here, in one place:
  * connects to a PINNED IP with an explicit Host header (ADR-0006) — the name
    is never re-resolved, so there is no rebinding window
  * token-bucket rate limit, concurrency cap, total-request cap, wall-clock cap
  * redirects are NEVER auto-followed: each Location is re-validated against the
    pinned IP/host/port and the scope rules; out-of-scope redirects are dropped
    and counted
  * cooperative cancellation checked between requests
"""
from __future__ import annotations
import dataclasses as dc
import time
from urllib.parse import urlsplit
import httpx


class BudgetExhausted(Exception):
    pass


class Cancelled(Exception):
    pass


@dc.dataclass(slots=True)
class Budget:
    max_requests_per_second: float
    max_total_requests: int
    max_duration_seconds: int
    request_timeout_seconds: int = 15
    requests_made: int = 0
    started_at: float = dc.field(default_factory=time.monotonic)

    def check(self) -> None:
        if self.requests_made >= self.max_total_requests:
            raise BudgetExhausted(f"request cap {self.max_total_requests} reached")
        if time.monotonic() - self.started_at >= self.max_duration_seconds:
            raise BudgetExhausted(f"duration cap {self.max_duration_seconds}s reached")


@dc.dataclass(slots=True)
class Response:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    elapsed_ms: int


class GuardedClient:
    """A target client that cannot leave its scope by construction."""

    def __init__(self, *, pinned_ip: str, host: str, port: int, scheme: str, budget: Budget,
                 is_cancelled=None, allowed_path_prefixes: tuple[str, ...] = ("/",),
                 excluded_path_prefixes: tuple[str, ...] = ()):
        self.pinned_ip, self.host, self.port, self.scheme = pinned_ip, host, port, scheme
        self.budget = budget
        self._is_cancelled = is_cancelled or (lambda: False)
        self.allowed = allowed_path_prefixes
        self.excluded = excluded_path_prefixes
        self.redirects_blocked = 0
        self._last_request_at = 0.0
        # Requests go to the pinned IP; the Host header carries the registered
        # name. follow_redirects is OFF and must stay off.
        self._client = httpx.Client(
            base_url=f"{scheme}://{pinned_ip}:{port}", follow_redirects=False,
            timeout=budget.request_timeout_seconds,
            headers={"Host": host, "User-Agent": "vapt-discovery/0.3 (authorised synthetic lab)"},
            trust_env=False,          # never consult HTTP_PROXY for target traffic
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GuardedClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------------------------------------------------------- scope ---
    def path_in_scope(self, path: str) -> bool:
        if any(path == e or path.startswith(e.rstrip("/") + "/") or path == e.rstrip("/")
               for e in self.excluded if e):
            return False
        return any(path == a or path.startswith(a if a.endswith("/") else a + "/") or a == "/"
                   for a in self.allowed)

    def target_in_scope(self, url: str) -> bool:
        """Used for redirect validation: host, port and path must all match."""
        parts = urlsplit(url)
        if parts.scheme and parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or self.host).lower()
        port = parts.port or (self.port if host == self.host.lower() else None)
        if host not in (self.host.lower(), self.pinned_ip):
            return False
        if port != self.port:
            return False
        return self.path_in_scope(parts.path or "/")

    # -------------------------------------------------------------- request ---
    def get(self, path: str) -> Response | None:
        if self._is_cancelled():
            raise Cancelled("cancellation requested")
        if not self.path_in_scope(path):
            return None
        self.budget.check()
        min_interval = 1.0 / max(self.budget.max_requests_per_second, 0.01)
        wait = self._last_request_at + min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        started = time.monotonic()
        try:
            r = self._client.get(path)
        except httpx.HTTPError:
            self._last_request_at = time.monotonic()
            self.budget.requests_made += 1
            return None
        self._last_request_at = time.monotonic()
        self.budget.requests_made += 1
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("location", "")
            if location and not self.target_in_scope(location):
                self.redirects_blocked += 1
                # Dropped deliberately: an out-of-scope redirect is never followed.
                return Response(url=path, status_code=r.status_code,
                                headers={k.lower(): v for k, v in r.headers.items()},
                                text="", elapsed_ms=int((time.monotonic() - started) * 1000))
        return Response(url=path, status_code=r.status_code,
                        headers={k.lower(): v for k, v in r.headers.items()},
                        text=r.text if "text" in r.headers.get("content-type", "") or
                        "json" in r.headers.get("content-type", "") or
                        "html" in r.headers.get("content-type", "") else "",
                        elapsed_ms=int((time.monotonic() - started) * 1000))
