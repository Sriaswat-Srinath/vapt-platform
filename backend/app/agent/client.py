"""LLM transport. The ONLY place an outbound model request is made.

Five refusals before anything leaves, in this order:

  1. LLM_ENABLED is false            -> disabled, nothing is attempted
  2. the host is not the configured provider -> the agent cannot pick a target
  3. the payload has not passed the stage-2 boundary -> see agent/boundary.py
  4. the payload exceeds the size cap -> truncation is the caller's problem
  5. the request exceeds its deadline -> the run fails, it does not retry forever

The route out is the CONNECT-only egress proxy. The api has no default route,
so there is no path that bypasses it: if the proxy refuses, the request fails.
The worker is not on an egress network at all and never calls this module.
"""
from __future__ import annotations
import dataclasses as dc
import json
import socket
import time
from urllib.parse import urlsplit

from ..config import settings
from .boundary import BoundaryRefusal, enforce

CLIENT_VERSION = "1.0.0"
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 256 * 1024


class LlmDisabled(RuntimeError):
    """LLM_ENABLED is false. The default, and not an error condition."""


class LlmRefused(RuntimeError):
    """The request was not made. Carries why."""


@dc.dataclass(frozen=True, slots=True)
class LlmResponse:
    text: str
    bytes_sent: int
    bytes_received: int
    elapsed_ms: int
    provider_host: str
    model: str


def _provider() -> tuple[str, int]:
    s = settings()
    host, _, port = (s.llm_provider_host or "").partition(":")
    if not host:
        raise LlmRefused("no LLM provider is configured")
    return host, int(port or s.llm_provider_port)


def _proxy() -> tuple[str, int]:
    s = settings()
    url = s.llm_proxy_url or ""
    parts = urlsplit(url if "//" in url else f"//{url}")
    if not parts.hostname:
        raise LlmRefused("no egress proxy is configured; the api has no direct route out")
    return parts.hostname, int(parts.port or 3128)


def send(payload: dict, *, timeout_s: float = 30.0) -> LlmResponse:
    """Send one request. The payload MUST be the object returned by enforce()."""
    s = settings()
    if not s.llm_enabled:
        raise LlmDisabled("LLM_ENABLED is false")

    checked, _report = enforce(payload)        # refuses rather than sends
    body = json.dumps(checked, separators=(",", ":")).encode()
    if len(body) > MAX_PAYLOAD_BYTES:
        raise LlmRefused(f"payload is {len(body)} bytes, over the {MAX_PAYLOAD_BYTES} cap")

    host, port = _provider()
    proxy_host, proxy_port = _proxy()
    started = time.monotonic()
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout_s)
    try:
        sock.settimeout(timeout_s)
        # CONNECT only: the proxy allowlists host:port and tunnels bytes. It
        # never sees the payload, and it refuses anything but the allowlisted
        # destination — including any host this code might be tricked into naming.
        sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        head = sock.recv(256).decode("latin-1", "replace")
        if " 200" not in head.split("\r\n")[0]:
            raise LlmRefused(f"the egress proxy refused the tunnel: {head.splitlines()[0]!r}")
        request = (
            f"POST {s.llm_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        sock.sendall(request)
        chunks: list[bytes] = []
        received = 0
        while received < MAX_RESPONSE_BYTES:
            chunk = sock.recv(16384)
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
    except (OSError, socket.timeout) as exc:
        raise LlmRefused(f"the request did not complete: {type(exc).__name__}: {exc}") from exc
    finally:
        sock.close()

    elapsed = int((time.monotonic() - started) * 1000)
    raw = b"".join(chunks).decode("utf-8", "replace")
    _head, _, text = raw.partition("\r\n\r\n")
    return LlmResponse(text=text or raw, bytes_sent=len(body), bytes_received=received,
                       elapsed_ms=elapsed, provider_host=f"{host}:{port}", model=s.llm_model)


__all__ = ["send", "LlmDisabled", "LlmRefused", "LlmResponse", "BoundaryRefusal",
           "CLIENT_VERSION"]
