"""Domain enumerations. Mirrors docs/DATA_MODEL.md; values are stable wire/DB strings."""
from __future__ import annotations
import enum


class StrEnum(str, enum.Enum):
    def __str__(self) -> str:                      # pragma: no cover
        return str(self.value)


class Role(StrEnum):
    analyst = "analyst"
    approver = "approver"
    admin = "admin"


class Protocol(StrEnum):
    http = "http"
    https = "https"


class AssetState(StrEnum):
    registered = "registered"
    active = "active"
    archived = "archived"


class Environment(StrEnum):
    mock_lab = "mock_lab"                          # the ONLY accepted value in the MVP


class ScopeRuleKind(StrEnum):
    include = "include"
    exclude = "exclude"


class GrantState(StrEnum):
    draft = "draft"
    active = "active"
    expired = "expired"
    revoked = "revoked"


class GrantDocumentState(StrEnum):
    unsigned_draft = "unsigned_draft"
    signed_verified = "signed_verified"
    mismatched = "mismatched"
    missing = "missing"


class ApprovalKind(StrEnum):
    scan_execution = "scan_execution"
    intrusive_profile = "intrusive_profile"
    report_export = "report_export"


class ApprovalState(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"
    invalidated = "invalidated"


class JobState(StrEnum):
    queued = "queued"
    preflight = "preflight"
    running = "running"
    paused = "paused"
    cancelling = "cancelling"
    cancelled = "cancelled"
    completed = "completed"
    failed = "failed"
    blocked = "blocked"


class ScanPhase(StrEnum):
    preflight = "preflight"
    spider = "spider"
    passive = "passive"
    active = "active"
    collect = "collect"
    normalize = "normalize"
    validate = "validate"
    score = "score"
    done = "done"


class JobStopReason(StrEnum):
    ok = "ok"
    budget_exhausted = "budget_exhausted"
    cancelled = "cancelled"
    grant_revoked = "grant_revoked"
    approval_invalidated = "approval_invalidated"
    daemon_unavailable = "daemon_unavailable"
    teardown_unconfirmed = "teardown_unconfirmed"
    cancel_unconfirmed = "cancel_unconfirmed"
    error = "error"


class Decision(StrEnum):
    allow = "allow"
    deny = "deny"


class ActorKind(StrEnum):
    human = "human"
    system = "system"
    agent = "agent"


class AuditOutcome(StrEnum):
    allow = "allow"
    deny = "deny"
    ok = "ok"
    error = "error"


class AssessmentState(StrEnum):
    discovered = "discovered"
    verified = "verified"
    inferred = "inferred"
    unassessed = "unassessed"
