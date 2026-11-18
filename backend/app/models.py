"""SQLAlchemy models — the deterministic backend's authoritative state.

Follows docs/DATA_MODEL.md. Safety-relevant invariants are expressed as database
constraints wherever possible, so they hold even under direct SQL:
  * assets.environment is CHECKed to 'mock_lab' and is immutable (trigger)
  * a scope grant cannot be active unless its document is signed_verified
  * validation_events may never be written by an agent
  * audit_log is append-only (no UPDATE/DELETE granted to the app role)
"""
from __future__ import annotations
import datetime as dt
from typing import Any
from sqlalchemy import (JSON, BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey,
                        Identity, Integer, String, Text, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from .ids import uuid7


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, list[str]: ARRAY(String)}


def _pk() -> Mapped[Any]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid7)


def _now() -> Mapped[dt.datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# --------------------------------------------------------------- identity ----
class Analyst(Base):
    __tablename__ = "analysts"
    id: Mapped[Any] = _pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (CheckConstraint("role in ('analyst','approver','admin')", name="ck_analyst_role"),)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[Any] = _pk()
    analyst_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _now()


class OperatorIdentity(Base):
    """A human, attested as distinct. Dual control counts THESE, not accounts."""
    __tablename__ = "operator_identities"
    id: Mapped[Any] = _pk()
    analyst_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"),
                                            unique=True, nullable=False)
    human_label: Mapped[str] = mapped_column(String(200), nullable=False)
    independence_attested_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    attested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    attestation_note: Mapped[str | None] = mapped_column(Text)
    attestation_withdrawn_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    deactivated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (
        CheckConstraint("independence_attested_by is null or independence_attested_by <> analyst_id",
                        name="ck_identity_no_self_attestation"),
    )


# ------------------------------------------------------------------ audit ----
class AuditLog(Base):
    """Append-only, hash-chained. Never UPDATEd or DELETEd by the application."""
    __tablename__ = "audit_log"
    id: Mapped[Any] = _pk()
    occurred_at: Mapped[dt.datetime] = _now()
    trace_id: Mapped[str | None] = mapped_column(String(64))
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    subject_type: Mapped[str | None] = mapped_column(String(60))
    subject_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(10), nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # A real database identity: the chain order must come from the DB, not the app.
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=False), unique=True,
                                     nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    __table_args__ = (CheckConstraint("actor_kind in ('human','system','agent')", name="ck_audit_actor"),)


# ------------------------------------------------------------------ asset ----
class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[Any] = _pk()
    asset_identifier: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    base_path: Mapped[str] = mapped_column(String(255), default="/", nullable=False)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="registered", nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    created_at: Mapped[dt.datetime] = _now()
    updated_at: Mapped[dt.datetime] = _now()
    __table_args__ = (
        UniqueConstraint("hostname", "port", name="uq_asset_host_port"),
        # The MVP accepts synthetic lab assets only. Widening this needs a
        # reviewed migration, not a code change (ADR-0011 R3 §13).
        CheckConstraint("environment = 'mock_lab'", name="ck_asset_environment_mock_lab"),
        CheckConstraint("protocol in ('http','https')", name="ck_asset_protocol"),
        CheckConstraint("port between 1 and 65535", name="ck_asset_port"),
        CheckConstraint("criticality between 1 and 5", name="ck_asset_criticality"),
    )


class ScopeRule(Base):
    __tablename__ = "scope_rules"
    id: Mapped[Any] = _pk()
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    host_pattern: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer)
    path_prefix: Mapped[str] = mapped_column(String(255), default="/", nullable=False)
    method_allowlist: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (CheckConstraint("kind in ('include','exclude')", name="ck_scope_rule_kind"),)


class ScopeGrant(Base):
    __tablename__ = "scope_grants"
    id: Mapped[Any] = _pk()
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="draft", nullable=False)
    document_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    document_sha256: Mapped[str | None] = mapped_column(String(64))
    document_state: Mapped[str] = mapped_column(String(20), default="unsigned_draft", nullable=False)
    document_verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    document_verified_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    document_signature_note: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"), nullable=False)
    approved_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    allowed_cidrs: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    allowed_ports: Mapped[list[str]] = mapped_column(ARRAY(Integer), nullable=False)
    allowed_profiles: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    intrusive_allowed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    valid_from: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (
        CheckConstraint("state in ('draft','active','expired','revoked')", name="ck_grant_state"),
        CheckConstraint("document_state in ('unsigned_draft','signed_verified','mismatched','missing')",
                        name="ck_grant_document_state"),
        # A grant cannot be ACTIVE unless its authorisation document is signed
        # and verified (owner instruction R2-14 / DATA_MODEL §11.4).
        CheckConstraint("state <> 'active' or document_state = 'signed_verified'",
                        name="ck_grant_active_requires_signed_document"),
        CheckConstraint("valid_until is null or valid_from is null or valid_until > valid_from",
                        name="ck_grant_validity_window"),
    )


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[Any] = _pk()
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    subject_type: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_id: Mapped[str | None] = mapped_column(String(64))
    scope_grant_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scope_grants.id"))
    requested_by: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"), nullable=False)
    decided_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    decision_note: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    independence_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    simulated_dual_control: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    invalidated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    invalidated_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (
        CheckConstraint("state in ('pending','approved','rejected','expired','invalidated')",
                        name="ck_approval_state"),
        # Dual control: an approval may never be decided by its requester.
        CheckConstraint("decided_by is null or decided_by <> requested_by",
                        name="ck_approval_distinct_parties"),
    )


class LabIsolationCheck(Base):
    """Ingested result of scripts/lab_isolation_check.sh. Gate 2 reads the latest."""
    __tablename__ = "lab_isolation_checks"
    id: Mapped[Any] = _pk()
    checked_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    network_name: Mapped[str | None] = mapped_column(String(80))
    subnet: Mapped[str | None] = mapped_column(String(64))
    egress_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False)
    dns_contained: Mapped[bool] = mapped_column(Boolean, nullable=False)
    isolation_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    host_hygiene_passed: Mapped[bool | None] = mapped_column(Boolean)
    host_wildcard_listeners: Mapped[str | None] = mapped_column(Text)
    probe_results: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    reported_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    created_at: Mapped[dt.datetime] = _now()


class ScopeDecision(Base):
    """Every preflight evaluation, allow or deny, is persisted."""
    __tablename__ = "scope_decisions"
    id: Mapped[Any] = _pk()
    subject_type: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_id: Mapped[str | None] = mapped_column(String(64))
    asset_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"))
    policy_version: Mapped[str] = mapped_column(String(20), nullable=False)
    decision: Mapped[str] = mapped_column(String(10), nullable=False)
    gate_results: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    resolved_ips: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    evaluated_at: Mapped[dt.datetime] = _now()
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(64))
    __table_args__ = (CheckConstraint("decision in ('allow','deny')", name="ck_decision"),)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id: Mapped[Any] = _pk()
    key: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    adapter_name: Mapped[str] = mapped_column(String(40), nullable=False)
    is_intrusive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    active_scan: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    max_requests_per_second: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    max_concurrent_requests: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    max_total_requests: Mapped[int] = mapped_column(Integer, default=5000, nullable=False)
    max_duration_seconds: Mapped[int] = mapped_column(Integer, default=1800, nullable=False)
    spider_max_depth: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    spider_max_children: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    excluded_path_patterns: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    method_denylist: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    excluded_rule_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    created_at: Mapped[dt.datetime] = _now()


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[Any] = _pk()
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    scope_grant_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scope_grants.id"))
    approval_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("approvals.id"))
    profile_key: Mapped[str] = mapped_column(String(60), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    phase: Mapped[str] = mapped_column(String(16), default="preflight", nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True)
    adapter_name: Mapped[str | None] = mapped_column(String(40))
    scope_decision_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scope_decisions.id"))
    pinned_ips: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    coverage_complete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requests_made: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # phase 4: daemon isolation bookkeeping (ADR-0008)
    # `fixture` replays recorded data and contacts nothing; `live` touches the
    # target and goes through the full gate chain. Recorded so the worker
    # re-evaluates in the SAME mode the request was admitted under.
    mode: Mapped[str] = mapped_column(String(10), default="live", nullable=False)
    requires_exclusive_daemon: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    daemon_lease_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True))
    session_asserted_empty_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    teardown_confirmed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    adapter_handle: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    cancel_requested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    observations_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stop_reason: Mapped[str | None] = mapped_column(String(32))
    error: Mapped[str | None] = mapped_column(Text)
    budget_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    trace_id: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    queued_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = _now()


class _ScanJobConstraints:
    pass


class ScanJobEvent(Base):
    __tablename__ = "scan_job_events"
    id: Mapped[Any] = _pk()
    job_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    at: Mapped[dt.datetime] = _now()
    from_state: Mapped[str | None] = mapped_column(String(16))
    to_state: Mapped[str] = mapped_column(String(16), nullable=False)
    phase: Mapped[str | None] = mapped_column(String(16))
    message: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


# ------------------------------------------------- discovery / attack surface --
class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"
    id: Mapped[Any] = _pk()
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    scope_grant_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scope_grants.id"))
    scope_decision_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scope_decisions.id"))
    source: Mapped[str] = mapped_column(String(10), nullable=False)      # fixture | live
    state: Mapped[str] = mapped_column(String(12), nullable=False)
    profile_key: Mapped[str | None] = mapped_column(String(60))
    pages_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requests_made: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    redirects_blocked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    coverage_complete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    stop_reason: Mapped[str | None] = mapped_column(String(32))
    error: Mapped[str | None] = mapped_column(Text)
    budget_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    pinned_ips: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    cancel_requested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    trace_id: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (
        CheckConstraint("source in ('fixture','live')", name="ck_discovery_source"),
        CheckConstraint("state in ('queued','running','completed','failed','cancelled','blocked')",
                        name="ck_discovery_state"),
    )


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[Any] = _pk()
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    first_seen_run_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("discovery_runs.id"))
    last_seen_run_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("discovery_runs.id"))
    url_normalized: Mapped[str] = mapped_column(String(1024), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    status_code_last: Mapped[int | None] = mapped_column(Integer)
    content_type_last: Mapped[str | None] = mapped_column(String(120))
    is_api: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    api_style: Mapped[str | None] = mapped_column(String(10))
    requires_auth_guess: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    auth_entry_kind: Mapped[str] = mapped_column(String(20), default="none", nullable=False)
    assessment: Mapped[str] = mapped_column(String(12), nullable=False)
    evidence_note: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[dt.datetime] = _now()
    last_seen_at: Mapped[dt.datetime] = _now()
    __table_args__ = (
        UniqueConstraint("asset_id", "url_normalized", "method", name="uq_endpoint_identity"),
        CheckConstraint("assessment in ('discovered','verified','inferred','unassessed')",
                        name="ck_endpoint_assessment"),
    )


class EndpointParameter(Base):
    __tablename__ = "endpoint_parameters"
    id: Mapped[Any] = _pk()
    endpoint_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    location: Mapped[str] = mapped_column(String(10), nullable=False)
    sample_value_redacted: Mapped[str | None] = mapped_column(String(200))
    inferred_type: Mapped[str | None] = mapped_column(String(20))
    is_required_guess: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    assessment: Mapped[str] = mapped_column(String(12), nullable=False)
    __table_args__ = (
        UniqueConstraint("endpoint_id", "name", "location", name="uq_param_identity"),
        CheckConstraint("location in ('query','path','body','header','cookie')", name="ck_param_location"),
    )


class Form(Base):
    __tablename__ = "forms"
    id: Mapped[Any] = _pk()
    endpoint_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=False)
    action_url_normalized: Mapped[str] = mapped_column(String(1024), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    enctype: Mapped[str | None] = mapped_column(String(80))
    has_csrf_token_field: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_login_candidate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    assessment: Mapped[str] = mapped_column(String(12), nullable=False)
    __table_args__ = (UniqueConstraint("endpoint_id", "action_url_normalized", "method",
                                       name="uq_form_identity"),)


class FormField(Base):
    __tablename__ = "form_fields"
    id: Mapped[Any] = _pk()
    form_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("forms.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    input_type: Mapped[str | None] = mapped_column(String(40))
    is_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    autocomplete: Mapped[str | None] = mapped_column(String(40))
    __table_args__ = (UniqueConstraint("form_id", "name", name="uq_form_field_identity"),)


class ResponseHeader(Base):
    __tablename__ = "response_headers"
    id: Mapped[Any] = _pk()
    endpoint_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=False)
    header_name: Mapped[str] = mapped_column(String(120), nullable=False)
    header_value_sample: Mapped[str | None] = mapped_column(String(400))
    present: Mapped[bool] = mapped_column(Boolean, nullable=False)
    observed_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    assessment: Mapped[str] = mapped_column(String(12), nullable=False)
    __table_args__ = (UniqueConstraint("endpoint_id", "header_name", name="uq_header_identity"),)


class CandidateTest(Base):
    """Deterministic surface -> candidate-test mapping (L2).

    These are TEST CANDIDATES, never findings. The agent may rank and explain
    them; a human accepts; the gate chain decides (MVP_SCOPE.md §5).
    """
    __tablename__ = "candidate_tests"
    id: Mapped[Any] = _pk()
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    endpoint_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("endpoints.id"))
    discovery_run_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("discovery_runs.id"))
    surface_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    concern: Mapped[str] = mapped_column(String(60), nullable=False)
    suggested_profile_key: Mapped[str | None] = mapped_column(String(60))
    requires_intrusive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    matrix_version: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[dt.datetime] = _now()
    __table_args__ = (UniqueConstraint("asset_id", "endpoint_id", "concern",
                                       name="uq_candidate_identity"),)


# ------------------------------------------------- scanner daemon / adapters --
class ScannerDaemonState(Base):
    """One row per adapter. Gate 13 reads it; only an audited, verification-gated
    reset may clear `is_dirty` (ADR-0008 R3 §10)."""
    __tablename__ = "scanner_daemon_state"
    adapter_name: Mapped[str] = mapped_column(String(40), primary_key=True)
    is_dirty: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False,
                                     server_default="false")
    dirty_reason: Mapped[str | None] = mapped_column(Text)
    dirty_since: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    dirty_job_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True))
    requires_operator_restart: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False,
                                     server_default="false")
    instance_marker: Mapped[str | None] = mapped_column(String(120))
    observed_version: Mapped[str | None] = mapped_column(String(40))
    last_reset_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_reset_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    last_reset_outcome: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    updated_at: Mapped[dt.datetime] = _now()


class ScannerDaemonLease(Base):
    """The GLOBAL exclusive lease. One `held` lease per adapter, enforced by a
    partial unique index: `newSession` is a daemon-global operation, so a
    per-asset lock cannot isolate jobs (ADR-0008 R2)."""
    __tablename__ = "scanner_daemon_leases"
    id: Mapped[Any] = _pk()
    adapter_name: Mapped[str] = mapped_column(String(40), nullable=False)
    lease_state: Mapped[str] = mapped_column(String(12), nullable=False)
    job_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"))
    holder_worker_id: Mapped[str | None] = mapped_column(String(80))
    acquired_at: Mapped[dt.datetime] = _now()
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    abandoned_reason: Mapped[str | None] = mapped_column(Text)
    daemon_dirty_on_release: Mapped[bool] = mapped_column(Boolean, default=False,
                                                          nullable=False,
                                                          server_default="false")
    __table_args__ = (
        CheckConstraint("lease_state in ('held','released','abandoned')", name="ck_lease_state"),
    )


class ScannerReset(Base):
    __tablename__ = "scanner_resets"
    id: Mapped[Any] = _pk()
    at: Mapped[dt.datetime] = _now()
    requested_by: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analysts.id"))
    adapter_name: Mapped[str] = mapped_column(String(40), nullable=False)
    steps: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cleared_dirty: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False,
                                                server_default="false")
    failing_step: Mapped[str | None] = mapped_column(String(12))
    trace_id: Mapped[str | None] = mapped_column(String(64))


class RawObservation(Base):
    """Verbatim scanner output. IMMUTABLE: never edited by normalisation,
    validation or scoring (ADR-0002). Findings link to these for provenance."""
    __tablename__ = "raw_observations"
    id: Mapped[Any] = _pk()
    job_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    asset_id: Mapped[Any] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    adapter_name: Mapped[str] = mapped_column(String(40), nullable=False)
    adapter_version: Mapped[str | None] = mapped_column(String(40))
    adapter_rule_id: Mapped[str | None] = mapped_column(String(60))
    captured_at: Mapped[dt.datetime] = _now()
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    request_sha256: Mapped[str | None] = mapped_column(String(64))
    response_sha256: Mapped[str | None] = mapped_column(String(64))
    observed_url: Mapped[str | None] = mapped_column(String(1024))
    observed_peer_ip: Mapped[str | None] = mapped_column(String(45))


class IngestionRejection(Base):
    """An observation refused at ingestion. Recorded here, never in
    raw_observations (ADR-0011 R3 §13)."""
    __tablename__ = "ingestion_rejections"
    id: Mapped[Any] = _pk()
    at: Mapped[dt.datetime] = _now()
    job_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"))
    asset_id: Mapped[Any | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"))
    reason: Mapped[str] = mapped_column(String(40), nullable=False)
    observed_url: Mapped[str | None] = mapped_column(String(1024))
    observed_peer_ip: Mapped[str | None] = mapped_column(String(45))
    payload_sha256: Mapped[str | None] = mapped_column(String(64))
    trace_id: Mapped[str | None] = mapped_column(String(64))
