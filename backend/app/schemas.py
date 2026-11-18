"""Request/response DTOs."""
from __future__ import annotations
import datetime as dt
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------- assets -------
class AssetCreate(BaseModel):
    asset_identifier: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=253)
    protocol: Literal["http", "https"] = "http"
    port: int = Field(ge=1, le=65535)
    base_path: str = "/"
    environment: Literal["mock_lab"] = "mock_lab"
    criticality: int = Field(default=1, ge=1, le=5)
    notes: str | None = None

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str) -> str:
        return v.strip().lower().rstrip(".")


class AssetUpdate(BaseModel):
    """Identity fields are deliberately absent: hostname, port, protocol and
    environment are immutable (invariant I14). Re-register instead."""
    display_name: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    notes: str | None = None


class AssetOut(ORM):
    id: Any
    asset_identifier: str
    display_name: str
    hostname: str
    protocol: str
    port: int
    base_path: str
    environment: str
    criticality: int
    state: str
    notes: str | None
    created_at: dt.datetime


# ---------------------------------------------------------------- scope -------
class ScopeRuleCreate(BaseModel):
    kind: Literal["include", "exclude"]
    host_pattern: str
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str = "/"
    method_allowlist: list[str] = Field(default_factory=list)
    reason: str | None = None


class ScopeRuleOut(ORM):
    id: Any
    kind: str
    host_pattern: str
    port: int | None
    path_prefix: str
    method_allowlist: list[str] | None
    reason: str | None


class ScopeValidateRequest(BaseModel):
    profile_key: str | None = None
    path: str = "/"
    method: str = "GET"


class GrantCreate(BaseModel):
    document_ref: str
    allowed_cidrs: list[str]
    allowed_ports: list[int]
    allowed_profiles: list[str]
    intrusive_allowed: bool = False
    valid_from: dt.datetime | None = None
    valid_until: dt.datetime | None = None


class GrantVerifyDocument(BaseModel):
    document_sha256: str = Field(min_length=64, max_length=64)
    signed: bool
    note: str | None = None


class GrantOut(ORM):
    id: Any
    asset_id: Any
    state: str
    document_ref: str
    document_sha256: str | None
    document_state: str
    allowed_cidrs: list[str]
    allowed_ports: list[int]
    allowed_profiles: list[str]
    intrusive_allowed: bool
    valid_from: dt.datetime | None
    valid_until: dt.datetime | None
    created_at: dt.datetime


# ------------------------------------------------------------ identities ------
class IdentityCreate(BaseModel):
    analyst_email: str
    human_label: str
    attestation_note: str | None = None


class IdentityOut(ORM):
    id: Any
    analyst_id: Any
    human_label: str
    attested_at: dt.datetime | None
    attestation_withdrawn_at: dt.datetime | None
    is_active: bool


# ----------------------------------------------------------------- jobs -------
class JobCreate(BaseModel):
    profile_key: str


class JobOut(ORM):
    id: Any
    asset_id: Any
    profile_key: str
    mode: str
    state: str
    phase: str
    adapter_name: str | None
    pinned_ips: list[str] | None
    coverage_complete: bool
    stop_reason: str | None
    queued_at: dt.datetime | None
    created_at: dt.datetime


class ProfileOut(ORM):
    key: str
    display_name: str
    adapter_name: str
    is_intrusive: bool
    active_scan: bool
    max_requests_per_second: int
    max_total_requests: int
    max_duration_seconds: int


# --------------------------------------------------------------- system -------
class IsolationReport(BaseModel):
    checked_at: dt.datetime
    valid_until: dt.datetime
    network_name: str | None = None
    subnet: str | None = None
    egress_blocked: bool
    dns_contained: bool
    isolation_passed: bool
    host_hygiene_passed: bool | None = None
    host_wildcard_listeners: str | None = None
    probe_results: list[dict[str, Any]] | None = None


class TokenIssued(BaseModel):
    token: str
    analyst_email: str
    role: str
    label: str
    expires_at: dt.datetime | None
