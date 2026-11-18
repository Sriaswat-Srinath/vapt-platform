"""Findings, evidence and validation history."""
from __future__ import annotations
import datetime as dt
from typing import Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import audit, errors, models
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


def _cvss_base(session: Session, finding_id: Any) -> float | None:
    risk = _risk(session, finding_id) or {}
    cvss = risk.get("cvss")
    return cvss.get("base") if isinstance(cvss, dict) else None


def _finding_or_404(session: Session, finding_id: str) -> models.Finding:
    row = session.get(models.Finding, finding_id)
    if row is None:
        raise errors.not_found("Finding")
    return row


def _risk(session: Session, finding_id) -> dict[str, object] | None:
    row = session.execute(select(models.RiskScore).where(
        models.RiskScore.finding_id == finding_id).order_by(
        models.RiskScore.computed_at.desc()).limit(1)).scalar_one_or_none()
    if row is None:
        return None
    return {
        # CVSS and any platform prioritisation are deliberately separate fields.
        "cvss": {"source": row.cvss_source, "version": row.cvss_version,
                 "vector": row.cvss_vector,
                 "base": float(row.cvss_base) if row.cvss_base is not None else None},
        "epss": float(row.epss_score) if row.epss_score is not None else None,
        "kev_listed": row.kev_listed,
        "priority_score": float(row.priority_score) if row.priority_score is not None else None,
        "priority_band": row.priority_band,
        "formula_version": row.formula_version,
        "note": (row.inputs or {}).get("note"),
        "cvss_reason": (row.inputs or {}).get("cvss_reason"),
    }


@router.get("/findings")
def list_findings(asset_id: str | None = None, job_id: str | None = None,
                  validation_state: str | None = None, severity: str | None = None,
                  include_suppressed: bool = False, limit: int = Query(default=100, le=500),
                  session: Session = Depends(get_session),
                  p: Principal = Depends(require_role("analyst", "approver"))):
    stmt = select(models.Finding).order_by(models.Finding.first_seen_at.desc()).limit(limit)
    if asset_id:
        stmt = stmt.where(models.Finding.asset_id == asset_id)
    if job_id:
        stmt = stmt.where(models.Finding.job_id == job_id)
    if validation_state:
        stmt = stmt.where(models.Finding.validation_state == validation_state)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if not include_suppressed:
        stmt = stmt.where(models.Finding.suppressed_at.is_(None))
    rows = session.execute(stmt).scalars().all()
    return [{"id": str(f.id), "title": f.title, "category": f.category,
             "affected_url": f.affected_url, "http_method": f.http_method,
             "parameter_name": f.parameter_name, "severity": f.severity,
             "confidence": f.confidence, "detection_source": f.detection_source,
             "validation_state": f.validation_state, "validation_rule_id": f.validation_rule_id,
             "catalogue_key": f.catalogue_key, "unmapped_rule_id": f.unmapped_rule_id,
             "coverage_complete": f.coverage_complete,
             "occurrence_count": f.occurrence_count,
             "quarantined": f.quarantined_at is not None,
             "cvss_base": _cvss_base(session, f.id),
             "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at} for f in rows]


@router.get("/assets/{asset_id}/findings/summary")
def findings_summary(asset_id: str, session: Session = Depends(get_session),
                     p: Principal = Depends(require_role("analyst", "approver"))):
    rows = session.execute(select(models.Finding).where(
        models.Finding.asset_id == asset_id)).scalars().all()
    by_state: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in rows:
        by_state[f.validation_state] = by_state.get(f.validation_state, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "total": len(rows), "by_validation_state": by_state, "by_severity": by_severity,
        "unmapped_detections": sum(1 for f in rows if f.unmapped_rule_id),
        "partial_coverage": sum(1 for f in rows if not f.coverage_complete),
        "note": ("Severity is the scanner's normalised risk. CVSS comes from the curated "
                 "catalogue. No platform prioritisation score is computed in this MVP."),
    }


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: str, session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst", "approver"))):
    f = _finding_or_404(session, finding_id)
    evidence = session.execute(select(models.Evidence).where(
        models.Evidence.finding_id == f.id).order_by(models.Evidence.collected_at)).scalars().all()
    obs_links = session.execute(select(models.FindingObservation).where(
        models.FindingObservation.finding_id == f.id)).scalars().all()
    provenance = []
    for link in obs_links:
        o = session.get(models.RawObservation, link.raw_observation_id)
        if o is not None:
            provenance.append({"raw_observation_id": str(o.id), "adapter": o.adapter_name,
                               "adapter_version": o.adapter_version,
                               "adapter_rule_id": o.adapter_rule_id,
                               "payload_sha256": o.payload_sha256,
                               "captured_at": o.captured_at})
    history = session.execute(select(models.ValidationEvent).where(
        models.ValidationEvent.finding_id == f.id).order_by(
        models.ValidationEvent.at)).scalars().all()
    catalogue = session.execute(select(models.VulnCatalogue).where(
        models.VulnCatalogue.key == f.catalogue_key)).scalar_one_or_none() \
        if f.catalogue_key else None
    return {
        "id": str(f.id), "title": f.title, "category": f.category,
        "affected_url": f.affected_url, "http_method": f.http_method,
        "parameter_name": f.parameter_name, "severity": f.severity, "confidence": f.confidence,
        "description_md": f.description_md, "remediation_md": f.remediation_md,
        "detection_source": f.detection_source, "fingerprint": f.fingerprint,
        "catalogue_key": f.catalogue_key, "unmapped_rule_id": f.unmapped_rule_id,
        "coverage_complete": f.coverage_complete, "occurrence_count": f.occurrence_count,
        "validation": {"state": f.validation_state, "rule_id": f.validation_rule_id,
                       "rule_version": f.validation_version},
        "risk": _risk(session, f.id),
        "catalogue": ({"cwe_ids": catalogue.cwe_ids, "default_severity": catalogue.default_severity,
                       "references": catalogue.references,
                       "catalogue_version": catalogue.catalogue_version}
                      if catalogue else None),
        "provenance": provenance,
        "evidence": [{"id": str(e.id), "kind": e.kind, "label": e.label,
                      "redaction_version": e.redaction_version,
                      "redaction_report": e.redaction_report,
                      "has_unredacted_original": e.blob_id is not None and e.blob_purged_at is None,
                      "collected_at": e.collected_at} for e in evidence],
        "validation_history": [{"at": h.at, "from_state": h.from_state, "to_state": h.to_state,
                                "rule_id": h.rule_id, "rule_version": h.rule_version,
                                "actor_kind": h.actor_kind, "actor_id": h.actor_id,
                                "justification": h.justification, "note": h.note,
                                "rule_inputs": h.rule_inputs} for h in history],
    }


@router.get("/evidence/{evidence_id}/content")
def evidence_content(evidence_id: str, raw: bool = False, justification: str | None = None,
                     session: Session = Depends(get_session),
                     p: Principal = Depends(require_role("analyst", "approver")),
                     trace: str = Depends(trace_id)):
    """Redacted content for analysts. The unredacted original requires `admin`
    AND a justification, and every access is audited (ADR-0011 R2)."""
    e = session.get(models.Evidence, evidence_id)
    if e is None:
        raise errors.not_found("Evidence")
    if not raw:
        return {"id": str(e.id), "kind": e.kind, "label": e.label, "redacted": True,
                "redaction_version": e.redaction_version,
                "redaction_report": e.redaction_report,
                "content": e.content_redacted}
    if p.role != "admin":
        raise errors.forbidden("the unredacted original requires the admin role")
    if not justification or len(justification.strip()) < 10:
        raise errors.bad_request("a justification of at least 10 characters is required to read "
                                 "unredacted evidence", "justification-required")
    if e.blob_id is None or e.blob_purged_at is not None:
        raise errors.conflict("blob-unavailable", "The unredacted original is unavailable",
                              "the blob has been purged; provenance hashes remain")
    from ...evidence import store
    blob = session.get(models.EvidenceBlob, e.blob_id)
    if blob is None or blob.state != "present":
        raise errors.conflict("blob-unavailable", "The unredacted original is unavailable",
                              f"blob state is {blob.state if blob else 'missing'!r}")
    try:
        data = store.read(blob)
    except (FileNotFoundError, ValueError) as exc:
        raise errors.conflict("blob-unavailable", "The unredacted original is unavailable",
                              str(exc)) from exc
    audit.record(session, action="raw_evidence_accessed", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="evidence", subject_id=str(e.id), trace_id=trace,
                 detail={"justification": justification[:500],
                         "content_sha256": blob.content_sha256})
    session.commit()
    return {"id": str(e.id), "kind": e.kind, "redacted": False,
            "content_sha256": blob.content_sha256,
            "content": data.decode("utf-8", "replace")}


@router.post("/findings/{finding_id}/analyst-classification")
def analyst_classification(finding_id: str, to_state: str, justification: str,
                           session: Session = Depends(get_session),
                           p: Principal = Depends(require_role("analyst", "approver")),
                           trace: str = Depends(trace_id)):
    """An analyst may override the classification WITH a justification.

    The automated result is preserved: validation_events is append-only, so the
    engine's transition and the human override coexist (decision D10).
    """
    allowed = {"candidate", "confirmed", "false_positive", "inconclusive", "not_applicable"}
    if to_state not in allowed:
        raise errors.bad_request(f"to_state must be one of {sorted(allowed)}")
    if len(justification.strip()) < 10:
        raise errors.bad_request("a justification of at least 10 characters is required",
                                 "justification-required")
    f = _finding_or_404(session, finding_id)
    evidence_ids = [str(e.id) for e in session.execute(select(models.Evidence).where(
        models.Evidence.finding_id == f.id)).scalars().all()]
    session.add(models.ValidationEvent(
        finding_id=f.id, from_state=f.validation_state, to_state=to_state,
        rule_id="analyst-override", rule_version=None,
        rule_inputs={"overrides_rule_id": f.validation_rule_id,
                     "overrides_rule_version": f.validation_version},
        evidence_ids=evidence_ids, actor_kind="human", actor_id=p.id,
        justification=justification.strip(), note="analyst override"))
    f.validation_state = to_state
    audit.record(session, action="finding_classification_overridden", actor_kind="human",
                 actor_id=p.id, outcome="ok", subject_type="finding", subject_id=str(f.id),
                 trace_id=trace, detail={"to_state": to_state,
                                         "justification": justification[:500]})
    session.commit()
    return {"id": str(f.id), "validation_state": f.validation_state,
            "note": "the automated classification is preserved in the validation history"}


@router.post("/findings/{finding_id}/suppress")
def suppress(finding_id: str, reason: str, session: Session = Depends(get_session),
             p: Principal = Depends(require_role("approver")), trace: str = Depends(trace_id)):
    if len(reason.strip()) < 10:
        raise errors.bad_request("a reason of at least 10 characters is required")
    f = _finding_or_404(session, finding_id)
    f.suppressed_at, f.suppression_reason = dt.datetime.now(dt.timezone.utc), reason.strip()
    audit.record(session, action="finding_suppressed", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="finding", subject_id=str(f.id), trace_id=trace,
                 detail={"reason": reason[:500]})
    session.commit()
    return {"id": str(f.id), "suppressed_at": f.suppressed_at}
