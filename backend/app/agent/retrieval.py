"""Execution of the read-only tool catalogue.

The decisions — which tools exist, what arguments are legal, which handle maps
to which finding — live in `toolspec.py`, which has no ORM dependency. This
module only RUNS a call that has already been validated, scoped to one asset.
"""
from __future__ import annotations
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models
from .toolspec import (MAX_ROWS, RETRIEVAL_VERSION, TOOLS, BY_NAME, Handles,  # noqa: F401
                       ReadTool, SEVERITIES, ToolRefused, VALIDATION_STATES,
                       definitions, _validate)

# --------------------------------------------------------------- executors ---
def _findings_query(session: Session, asset_id: Any, args: dict):
    stmt = select(models.Finding).where(
        models.Finding.asset_id == asset_id,
        models.Finding.quarantined_at.is_(None))
    if "validation_state" in args:
        stmt = stmt.where(models.Finding.validation_state == args["validation_state"])
    if "category" in args:
        stmt = stmt.where(models.Finding.category == args["category"])
    if "severity" in args:
        stmt = stmt.where(models.Finding.severity == args["severity"])
    return stmt.order_by(models.Finding.last_seen_at.desc()).limit(args.get("limit", 20))


def execute(session: Session, *, asset: models.Asset, handles: Handles,
            name: str, arguments: dict) -> dict[str, Any]:
    """Run one read. Raises ToolRefused; never mutates anything."""
    args = _validate(name, arguments)

    if name == "list_findings":
        rows = session.execute(_findings_query(session, asset.id, args)).scalars().all()
        return {"findings": [{
            "handle": handles.handle_for(str(f.id)),
            "title": f.title, "category": f.category, "severity": f.severity,
            "validation_state": f.validation_state,
            "path": f.affected_url.split("://", 1)[-1].partition("/")[2][:160],
            "parameter": f.parameter_name,
            "coverage_complete": bool(f.coverage_complete),
            "occurrences": f.occurrence_count,
        } for f in rows], "total_returned": len(rows)}

    if name == "get_finding":
        finding = session.get(models.Finding, handles.id_for(str(arguments.get("handle"))))
        if finding is None or finding.asset_id != asset.id:
            raise ToolRefused("not found", "that finding does not belong to this application")
        evidence = session.execute(select(models.Evidence).where(
            models.Evidence.finding_id == finding.id)).scalars().all()
        risk = session.execute(select(models.RiskScore).where(
            models.RiskScore.finding_id == finding.id)).scalars().first()
        provenance = session.execute(
            select(models.RawObservation)
            .join(models.FindingObservation,
                  models.FindingObservation.raw_observation_id == models.RawObservation.id)
            .where(models.FindingObservation.finding_id == finding.id).limit(5)).scalars().all()
        return {"finding": {
            "handle": handles.handle_for(str(finding.id)),
            "title": finding.title, "category": finding.category,
            "severity": finding.severity, "validation_state": finding.validation_state,
            "validation_rule_id": finding.validation_rule_id,
            "path": finding.affected_url.split("://", 1)[-1].partition("/")[2][:200],
            "parameter": finding.parameter_name,
            "catalogue_key": finding.catalogue_key,
            "unmapped_rule_id": finding.unmapped_rule_id,
            "coverage_complete": bool(finding.coverage_complete),
            "description": finding.description_md,
            "curated_remediation": finding.remediation_md,
            "cvss": ({"base": float(risk.cvss_base), "vector": risk.cvss_vector,
                      "source": risk.cvss_source} if risk and risk.cvss_base else None),
            "provenance": [{"adapter": p.adapter_name, "rule": p.adapter_rule_id}
                           for p in provenance],
            # Redacted text only, and excerpted.
            "evidence_excerpt": [(e.content_redacted or "")[:800] for e in evidence][:3],
        }}

    if name == "get_coverage":
        from ..api.v1.taxonomy_api import _coverage_rows
        rows = _coverage_rows(session, asset)
        return {"coverage": [{
            "category": r.key, "name": r.display_name, "tier": r.tier,
            "priority": r.priority, "detection": r.detection,
            "catalogue_entries": r.catalogue_entries, "surfaces_flagged": r.candidates,
            "findings": r.findings_total, "blocked_by": list(r.blocked_by),
        } for r in rows if r.tier == 1]}

    if name == "list_assessments":
        rows = session.execute(select(models.ScanJob).where(
            models.ScanJob.asset_id == asset.id).order_by(
            models.ScanJob.created_at.desc()).limit(args.get("limit", 10))).scalars().all()
        return {"assessments": [{
            "mode": j.mode, "profile": j.profile_key, "state": j.state,
            "coverage_complete": bool(j.coverage_complete), "stop_reason": j.stop_reason,
            "started": j.created_at.isoformat() if j.created_at else None,
        } for j in rows]}

    if name == "list_candidate_tests":
        rows = session.execute(select(models.CandidateTest).where(
            models.CandidateTest.asset_id == asset.id).limit(
            args.get("limit", 25))).scalars().all()
        return {"candidate_tests": [{
            "concern": c.concern, "surface": c.surface_kind,
            "requires_intrusive": bool(c.requires_intrusive),
        } for c in rows], "note": "candidate tests are surfaces worth examining, not findings"}

    if name == "list_reports":
        rows = session.execute(select(models.Report).where(
            models.Report.asset_id == asset.id).order_by(
            models.Report.generated_at.desc()).limit(args.get("limit", 5))).scalars().all()
        out = []
        for r in rows:
            arts = session.execute(select(models.ReportArtifact).where(
                models.ReportArtifact.report_id == r.id)).scalars().all()
            out.append({"title": r.title, "state": r.state,
                        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                        "formats": [a.format for a in arts if not a.unavailable_reason]})
        return {"reports": out}

    if name == "get_scope_and_authorisation":
        grant = session.execute(select(models.ScopeGrant).where(
            models.ScopeGrant.asset_id == asset.id).order_by(
            models.ScopeGrant.created_at.desc()).limit(1)).scalar_one_or_none()
        rules = session.execute(select(models.ScopeRule).where(
            models.ScopeRule.asset_id == asset.id)).scalars().all()
        jobs_live = int(session.execute(
            select(func.count()).select_from(models.ScanJob).where(
                models.ScanJob.asset_id == asset.id,
                models.ScanJob.mode == "live",
                models.ScanJob.state == "completed")).scalar_one())
        return {"authorisation": {
            "document_state": grant.document_state if grant else "none",
            "grant_state": grant.state if grant else "none",
            "intrusive_allowed": bool(grant.intrusive_allowed) if grant else False,
        }, "scope_rules": [{"kind": r.kind, "path_prefix": r.path_prefix,
                            "methods": list(r.method_allowlist or []), "reason": r.reason}
                           for r in rules],
            "live_assessments_completed": jobs_live,
            "note": ("A live assessment requires a signed authorisation document and all "
                     "thirteen preflight gates to pass.")}

    raise ToolRefused("unknown tool", name)       # pragma: no cover - guarded above
