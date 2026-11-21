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
    # How long an authorisation-document digest attestation stays usable. The
    # document is the authority for a live scan, so its integrity is re-checked
    # rather than assumed to hold indefinitely.
    authorisation_attestation_ttl_minutes: int = 1440

    # ---- the agent (L3, advisory only) -------------------------------------
    # Disabled by default. Enabling it grants the agent nothing but the ability
    # to be ASKED: it proposes from a fixed catalogue and sets no state.
    llm_enabled: bool = False
    # The model. Haiku 4.5 is the configured default: the per-tool prompts are
    # 400-1200 tokens, the output is short structured JSON, and the platform
    # validates everything it returns, so the task does not need a larger model.
    # NOTE: Haiku 4.5 has no `effort` setting — sending one is an error — and
    # takes an explicit thinking budget rather than adaptive thinking.
    llm_model: str = "claude-haiku-4-5"
    llm_max_output_tokens: int = 4096
    llm_thinking_budget_tokens: int = 0        # 0 = no thinking; >=1024 to enable
    llm_structured_output: bool = True
    llm_max_retries: int = 1
    # Empty = the SDK's default (https://api.anthropic.com). Pointed at the
    # local stand-in for tests, which speaks the Messages API shape over HTTP.
    llm_base_url: str = "https://llm-standin:8443"
    # Trust anchor for the TEST stand-in. Unset for a real provider, which is
    # verified against the system trust store.
    llm_ca_bundle: str | None = None
    # The ONLY route out. The api has no default route of its own.
    llm_proxy_url: str = "http://172.30.22.60:3128"
    # Never defaulted, never logged, never placed in a payload: it travels as an
    # SDK header. The stage-2 boundary refuses any payload containing it.
    anthropic_api_key: str | None = None
    # ---- conversational analyst --------------------------------------------
    # Cost controls, not safety controls: a chat loop that talks to a paid API
    # needs a floor, and "it got expensive" should be a refusal, not a surprise.
    llm_run_token_budget: int = 60_000
    llm_conversation_token_budget: int = 120_000
    llm_daily_token_budget: int = 2_000_000
    llm_history_turns: int = 12
    llm_max_question_chars: int = 2000

    llm_max_findings: int = 25
    # How many findings get an explanation + remediation pair. Each is two
    # requests, so this is the main cost dial.
    llm_max_explanations: int = 5
    llm_timeout_seconds: int = 60

    # ---- retention (phase 8) -----------------------------------------------
    # Purge deletes UNREDACTED BLOBS only, and only when nothing references
    # them. Disabled by default: deleting evidence is irreversible, so it is an
    # explicit operator decision, and the API's purge endpoint is dry-run
    # unless asked otherwise.
    # Evidence encryption at rest. OFF by default: an operator who enables it
    # and loses EVIDENCE_ENCRYPTION_KEY has lost their evidence, so it is a
    # deliberate decision. Existing plaintext blobs stay readable either way.
    evidence_encryption_enabled: bool = False

    retention_enabled: bool = False
    retention_evidence_blob_days: int = 90
    retention_batch_limit: int = 200
    retention_schedule_minutes: int = 1440

    # ---- API rate limiting (phase 8) ---------------------------------------
    # Availability protection, not a security boundary: a limiter that fails
    # closed would turn a Redis blip into an outage. On Redis failure the
    # in-process limiter still applies, so there is always A limit.
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 240
    rate_limit_write_per_minute: int = 60
    rate_limit_burst: int = 30

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
