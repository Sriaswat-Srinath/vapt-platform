"""Adapter registry. `mock` is always available; `zap` only when explicitly
enabled, so the default posture contacts nothing."""
from __future__ import annotations
from ..config import settings
from .base import ScannerAdapter


def registered_adapters() -> dict[str, str]:
    s = settings()
    out = {"mock": "available"}
    out["zap"] = "available" if s.zap_adapter_enabled else "disabled (ZAP_ADAPTER_ENABLED=false)"
    return out


def get_adapter(name: str) -> ScannerAdapter:
    s = settings()
    if name == "mock":
        from .mock.adapter import MockAdapter
        return MockAdapter()
    if name == "zap":
        if not s.zap_adapter_enabled:
            raise RuntimeError("the zap adapter is disabled (ZAP_ADAPTER_ENABLED=false)")
        from .zap.adapter import ZapAdapter
        return ZapAdapter()
    raise RuntimeError(f"unknown scanner adapter {name!r}")
