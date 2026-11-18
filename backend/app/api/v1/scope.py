"""Scope rules, grants, approvals, operator identities, and the dry-run
scope validation endpoint."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import audit, errors, models, schemas, services
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


def _asset_or_404(session: Session, asset_id: str) -> models.Asset:
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    return asset


# ------------------------------------------------------------ scope rules -----
@router.get("/assets/{asset_id}/scope-rules", response_model=list[schemas.ScopeRuleOut])
def list_rules(asset_id: str, session: Session = Depends(get_session),
               p: Principal = Depends(require_role("analyst", "approver"))):
    _asset_or_404(session, asset_id)
    return session.execute(select(models.ScopeRule).where(
        models.ScopeRule.asset_id == asset_id)).scalars().all()


@router.post("/assets/{asset_id}/scope-rules", response_model=schemas.ScopeRuleOut, status_code=201)
def add_rule(asset_id: str, payload: schemas.ScopeRuleCreate,
             session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst")),
             trace: str = Depends(trace_id)):
    asset = _asset_or_404(session, asset_id)
    if payload.kind == "include" and payload.host_pattern != asset.hostname:
        raise errors.conflict(
            "scope-rule-out-of-asset", "Include rule outside the asset",
            f"an include rule may only name the registered hostname {asset.hostname!r}; "
            f"{payload.host_pattern!r} was requested")
    if payload.kind == "include" and payload.port not in (None, asset.port):
        raise errors.conflict("scope-rule-out-of-asset", "Include rule outside the asset",
                              f"an include rule may only name the registered port {asset.port}")
    rule = models.ScopeRule(asset_id=asset.id, created_by=p.analyst.id, **payload.model_dump())
    session.add(rule)
    audit.record(session, action="scope_rule_added", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scope_rule", subject_id=str(asset.id), trace_id=trace,
                 detail=payload.model_dump())
    session.commit()
    return rule


@router.delete("/scope-rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, session: Session = Depends(get_session),
                p: Principal = Depends(require_role("analyst")), trace: str = Depends(trace_id)):
    rule = session.get(models.ScopeRule, rule_id)
    if rule is None:
        raise errors.not_found("Scope rule")
    audit.record(session, action="scope_rule_deleted", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scope_rule", subject_id=str(rule.id), trace_id=trace)
    session.delete(rule)
    session.commit()


# ------------------------------------------------------- scope validation -----
@router.post("/assets/{asset_id}/scope/validate")
def validate_scope(asset_id: str, payload: schemas.ScopeValidateRequest,
                   session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst", "approver"))):
    """Dry run of the full gate chain. Persists the decision like any other."""
    asset = _asset_or_404(session, asset_id)
    result, row = services.evaluate_and_persist(
        session, asset=asset, profile_key=payload.profile_key, path=payload.path,
        method=payload.method, actor_id=p.id, subject_type="scope_validation",
        short_circuit=False)
    session.commit()
    return {"scope_decision_id": str(row.id), **result.as_dict()}


# -------------------------------------------------------------- grants --------
@router.get("/assets/{asset_id}/scope-grants", response_model=list[schemas.GrantOut])
def list_grants(asset_id: str, session: Session = Depends(get_session),
                p: Principal = Depends(require_role("analyst", "approver"))):
    _asset_or_404(session, asset_id)
    return session.execute(select(models.ScopeGrant).where(
        models.ScopeGrant.asset_id == asset_id)).scalars().all()


@router.post("/assets/{asset_id}/scope-grants", response_model=schemas.GrantOut, status_code=201)
def create_grant(asset_id: str, payload: schemas.GrantCreate,
                 session: Session = Depends(get_session),
                 p: Principal = Depends(require_role("analyst")),
                 trace: str = Depends(trace_id)):
    """Creates a DRAFT grant. It cannot be activated until the authorisation
    document is signed and verified (DB CHECK + gate 5)."""
    asset = _asset_or_404(session, asset_id)
    grant = models.ScopeGrant(asset_id=asset.id, requested_by=p.analyst.id, state="draft",
                              document_state="unsigned_draft", **payload.model_dump())
    session.add(grant)
    audit.record(session, action="scope_grant_drafted", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scope_grant", subject_id=str(asset.id),
                 trace_id=trace, detail={"document_ref": payload.document_ref})
    session.commit()
    return grant


@router.post("/scope-grants/{grant_id}/verify-document", response_model=schemas.GrantOut)
def verify_document(grant_id: str, payload: schemas.GrantVerifyDocument,
                    session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("admin")),
                    trace: str = Depends(trace_id)):
    """Record that a human has verified the authorisation document.

    `signed=false` is recorded as `unsigned_draft`, which keeps activation
    impossible. No code path sets signed_verified on its own.
    """
    grant = session.get(models.ScopeGrant, grant_id)
    if grant is None:
        raise errors.not_found("Scope grant")
    grant.document_sha256 = payload.document_sha256
    grant.document_state = "signed_verified" if payload.signed else "unsigned_draft"
    grant.document_verified_at = dt.datetime.now(dt.timezone.utc)
    grant.document_verified_by = p.analyst.id
    grant.document_signature_note = payload.note
    audit.record(session, action="scope_grant_document_verified", actor_kind="human",
                 actor_id=p.id, outcome="ok", subject_type="scope_grant",
                 subject_id=str(grant.id), trace_id=trace,
                 detail={"document_state": grant.document_state,
                         "document_sha256": payload.document_sha256})
    session.commit()
    return grant


@router.post("/scope-grants/{grant_id}/activate", response_model=schemas.GrantOut)
def activate_grant(grant_id: str, session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("approver")),
                   trace: str = Depends(trace_id)):
    grant = session.get(models.ScopeGrant, grant_id)
    if grant is None:
        raise errors.not_found("Scope grant")
    if grant.document_state != "signed_verified":
        raise errors.conflict(
            "authorisation-unsigned", "Authorisation document is not signed and verified",
            f"grant {grant.id} cannot be activated while its document state is "
            f"{grant.document_state!r}. Scanner execution remains denied.",
            {"document_ref": grant.document_ref, "document_state": grant.document_state})
    if grant.requested_by == p.analyst.id:
        raise errors.conflict("same-party", "Activation requires a second party",
                              "a grant may not be activated by the analyst who requested it")
    grant.state = "active"
    grant.approved_by = p.analyst.id
    if grant.valid_from is None:
        grant.valid_from = dt.datetime.now(dt.timezone.utc)
    audit.record(session, action="scope_grant_activated", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scope_grant", subject_id=str(grant.id), trace_id=trace)
    session.commit()
    return grant


@router.post("/scope-grants/{grant_id}/revoke", response_model=schemas.GrantOut)
def revoke_grant(grant_id: str, reason: str, session: Session = Depends(get_session),
                 p: Principal = Depends(require_role("approver")),
                 trace: str = Depends(trace_id)):
    grant = session.get(models.ScopeGrant, grant_id)
    if grant is None:
        raise errors.not_found("Scope grant")
    grant.state, grant.revoked_at = "revoked", dt.datetime.now(dt.timezone.utc)
    grant.revocation_reason = reason
    audit.record(session, action="scope_grant_revoked", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="scope_grant", subject_id=str(grant.id),
                 trace_id=trace, detail={"reason": reason})
    session.commit()
    return grant


# --------------------------------------------------- operator identities ------
@router.get("/operator-identities", response_model=list[schemas.IdentityOut])
def list_identities(session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("approver"))):
    return session.execute(select(models.OperatorIdentity)).scalars().all()


@router.post("/operator-identities", response_model=schemas.IdentityOut, status_code=201)
def attest_identity(payload: schemas.IdentityCreate, session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("admin")),
                    trace: str = Depends(trace_id)):
    """Attest that an account corresponds to a DISTINCT human.

    An admin cannot attest their own independence (DB CHECK). This is a recorded
    human claim and nothing more is claimed for it (ADR-0009).
    """
    analyst = session.execute(select(models.Analyst).where(
        models.Analyst.email == payload.analyst_email)).scalar_one_or_none()
    if analyst is None:
        raise errors.not_found("Analyst")
    if analyst.id == p.analyst.id:
        raise errors.conflict("self-attestation", "Self-attestation is not permitted",
                              "nobody may attest their own independence")
    row = models.OperatorIdentity(
        analyst_id=analyst.id, human_label=payload.human_label,
        independence_attested_by=p.analyst.id, attested_at=dt.datetime.now(dt.timezone.utc),
        attestation_note=payload.attestation_note)
    session.add(row)
    audit.record(session, action="operator_identity_attested", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="operator_identity", subject_id=str(analyst.id),
                 trace_id=trace, detail={"human_label": payload.human_label})
    session.commit()
    return row
