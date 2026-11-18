"""Configuration. Every value from the environment, validated at startup.

Safety-relevant flags default to the SAFE value and several are NOT disableable:
a startup check rejects the unsafe value outright rather than honouring it
(docs/CONFIGURATION.md).
"""
from __future__ import annotations
from functools import lru_cache
from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: Literal["dev", "ci", "prod"] = "dev"
    secret_key: str = Field(min_length=16)
    api_base_path: str = "/api/v1"
    api_bind_ip: str = "172.30.20.20"              # vapt_edge interface ONLY
    api_port: int = 8000
    log_level: str = "INFO"

    database_url: str
    redis_url: str = "redis://172.30.21.50:6379/0"
    redis_password: str | None = None

    # ---- scanner execution gates (all default to the safe value) -----------
    scanner_execution_enabled: bool = False
    zap_adapter_enabled: bool = False
    active_scan_enabled: bool = False
    dual_control_available: bool = False
    default_scanner_adapter: str = "mock"
    isolation_check_ttl_minutes: int = 60
    max_concurrent_jobs_global: int = 2
    max_concurrent_jobs_per_asset: int = 1

    # ---- not disableable ---------------------------------------------------
    require_signed_authorisation: bool = True
    dual_control_min_identities: int = 2
    approval_invalidation_on_identity_change: bool = True
    ingestion_enforce_pinned_peer: bool = True
    suppress_negative_evidence_on_partial_coverage: bool = True

    lab_subnet: str = "172.30.10.0/24"
    llm_enabled: bool = False

    @field_validator("default_scanner_adapter")
    @classmethod
    def _adapter(cls, v: str) -> str:
        if v not in {"mock", "zap"}:
            raise ValueError("default_scanner_adapter must be 'mock' or 'zap'")
        return v

    def assert_safe(self) -> None:
        """Refuse to start on a weakened safety default (CONFIGURATION.md §13)."""
        problems = []
        if not self.require_signed_authorisation:
            problems.append("REQUIRE_SIGNED_AUTHORISATION=false is not permitted")
        if self.dual_control_min_identities < 2:
            problems.append("DUAL_CONTROL_MIN_IDENTITIES must be >= 2")
        if not self.approval_invalidation_on_identity_change:
            problems.append("APPROVAL_INVALIDATION_ON_IDENTITY_CHANGE=false is not permitted")
        if not self.ingestion_enforce_pinned_peer:
            problems.append("INGESTION_ENFORCE_PINNED_PEER=false is not permitted")
        if not self.suppress_negative_evidence_on_partial_coverage:
            problems.append("SUPPRESS_NEGATIVE_EVIDENCE_ON_PARTIAL_COVERAGE=false is not permitted")
        if self.zap_adapter_enabled and self.default_scanner_adapter != "zap":
            pass  # allowed: adapter registered but not default
        if problems:
            raise RuntimeError("refusing to start: " + "; ".join(problems))


@lru_cache
def settings() -> Settings:
    s = Settings()           # type: ignore[call-arg]
    s.assert_safe()
    return s
