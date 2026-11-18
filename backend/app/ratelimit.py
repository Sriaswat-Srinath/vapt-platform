"""API rate limiting.

This protects availability, not a security boundary — the gate chain, the
authorisation controls and the redaction boundary are elsewhere and do not
depend on it. That distinction decides the failure mode: a limiter that failed
closed would turn a Redis hiccup into an outage of the whole platform, so when
the shared counter is unavailable the request is still limited, just by an
in-process counter instead. There is never NO limit.

Two classes, because they have different costs:
  reads   GET/HEAD/OPTIONS          — generous
  writes  POST/PUT/PATCH/DELETE     — tighter; these start jobs and generate reports

The key is the authenticated principal where there is one, and the client
address otherwise, so one analyst cannot exhaust another's budget.
"""
from __future__ import annotations
import threading
import time

from .config import settings

WINDOW_SECONDS = 60
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Liveness and readiness must never be rate limited: a limiter that can stop a
# healthcheck can restart the container it is protecting.
EXEMPT_PATHS = ("/system/health", "/system/readiness")

_local_lock = threading.Lock()
_local_counters: dict[tuple[str, int], int] = {}


def _local_hit(key: str, window: int, limit: int) -> tuple[bool, int]:
    """In-process fixed window. The fallback, and the floor."""
    with _local_lock:
        bucket = (key, window)
        count = _local_counters.get(bucket, 0) + 1
        _local_counters[bucket] = count
        if len(_local_counters) > 10_000:                 # bounded memory
            for k in [k for k in _local_counters if k[1] != window]:
                _local_counters.pop(k, None)
    return count <= limit, max(0, limit - count)


def _redis_hit(key: str, window: int, limit: int) -> tuple[bool, int] | None:
    """Shared fixed window. Returns None when Redis cannot answer."""
    try:
        import redis                                      # local import: optional path
        s = settings()
        client = redis.Redis.from_url(s.redis_url, password=s.redis_password,
                                      socket_timeout=0.25, socket_connect_timeout=0.25)
        redis_key = f"vapt:rl:{key}:{window}"
        pipe = client.pipeline()
        pipe.incr(redis_key, 1)
        pipe.expire(redis_key, WINDOW_SECONDS * 2)
        count = int(pipe.execute()[0])
        return count <= limit, max(0, limit - count)
    except Exception:                                     # noqa: BLE001 - fail OPEN to local
        return None


def check(*, principal: str, method: str, path: str) -> tuple[bool, int, int, str]:
    """Returns (allowed, remaining, retry_after_seconds, limiter)."""
    s = settings()
    if not s.rate_limit_enabled or any(path.endswith(p) for p in EXEMPT_PATHS):
        return True, -1, 0, "exempt"

    is_read = method.upper() in READ_METHODS
    limit = s.rate_limit_per_minute if is_read else s.rate_limit_write_per_minute
    window = int(time.time() // WINDOW_SECONDS)
    key = f"{principal}:{'r' if is_read else 'w'}"

    shared = _redis_hit(key, window, limit)
    if shared is not None:
        allowed, remaining = shared
        limiter = "redis"
    else:
        allowed, remaining = _local_hit(key, window, limit)
        limiter = "in-process (shared counter unavailable)"
    retry_after = WINDOW_SECONDS - int(time.time() % WINDOW_SECONDS)
    return allowed, remaining, retry_after, limiter


def reset_local() -> None:
    """Test hook. Only clears the in-process counters."""
    with _local_lock:
        _local_counters.clear()
