"""Report generation and download."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import audit, errors, models
from ...db import get_session
from ...deps import Principal, require_role, trace_id
from ...evidence import store
from ...reporting import assembler, renderers

router = APIRouter()

DEFAULT_STATES = ("confirmed", "inconclusive", "candidate")


@router.get("/report-templates")
def templates(p: Principal = Depends(require_role("analyst", "approver"))):
    return [{"key": assembler.TEMPLATE_KEY, "version": assembler.TEMPLATE_VERSION,
             "sections": ["executive_summary", "scope", "methodology", "attack_surface",
                          "vulnerability_summary", "findings", "risk_prioritisation",
                          "remediation", "coverage", "limitations"],
             "formats": ["html", "json", "pdf"],
             "note": ("HTML and JSON are always produced. PDF is attempted and recorded as "
                      "unavailable with a reason if its native libraries are absent.")}]


@router.post("/assets/{asset_id}/reports", status_code=201)
def generate(asset_id: str, include_states: str = Query(default=",".join(DEFAULT_STATES)),
             job_ids: str | None = None, session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst")), trace: str = Depends(trace_id)):
    """Assemble and render a report from stored assessment data."""
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    states = tuple(s.strip() for s in include_states.split(",") if s.strip())
    valid = {"candidate", "confirmed", "false_positive", "inconclusive", "not_applicable"}
    if not set(states) <= valid:
        raise errors.bad_request(f"include_states must be a subset of {sorted(valid)}")
    if job_ids:
        ids = [j.strip() for j in job_ids.split(",") if j.strip()]
    else:
        ids = [str(j.id) for j in session.execute(select(models.ScanJob).where(
            models.ScanJob.asset_id == asset.id,
            models.ScanJob.state.in_(("completed", "cancelled"))).order_by(
            models.ScanJob.created_at.desc()).limit(20)).scalars().all()]
    grant = session.execute(select(models.ScopeGrant).where(
        models.ScopeGrant.asset_id == asset.id).order_by(
        models.ScopeGrant.created_at.desc()).limit(1)).scalar_one_or_none()
    runs = [str(r.id) for r in session.execute(select(models.DiscoveryRun).where(
        models.DiscoveryRun.asset_id == asset.id)).scalars().all()]

    report = models.Report(
        asset_id=asset.id, state="generating",
        title=f"Web application security assessment — {asset.asset_identifier}",
        scope_grant_id=grant.id if grant else None, job_ids=ids, discovery_run_ids=runs,
        template_key=assembler.TEMPLATE_KEY, template_version=assembler.TEMPLATE_VERSION,
        filter={"include_states": list(states)}, generated_by=p.analyst.id)
    session.add(report)
    session.flush()
    try:
        sections = assembler.build(session, asset=asset, job_ids=ids, include_states=states)
        for s in sections:
            session.add(models.ReportSection(report_id=report.id, seq=s["seq"], key=s["key"],
                                             heading=s["heading"], body_md=s.get("body_md"),
                                             data=s.get("data")))
        asset_dict = {"asset_identifier": asset.asset_identifier, "hostname": asset.hostname,
                      "port": asset.port, "protocol": asset.protocol,
                      "environment": asset.environment, "display_name": asset.display_name}
        meta = {"report_id": str(report.id), "title": report.title,
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "template_key": report.template_key, "template_version": report.template_version,
                "include_states": list(states), "job_ids": ids}
        html_bytes = renderers.render_html(asset=asset_dict, sections=sections, meta=meta)
        json_bytes = renderers.render_json(asset=asset_dict, sections=sections, meta=meta)
        pdf_bytes, pdf_reason = renderers.render_pdf(html_bytes)

        # Pin the evidence this report cites. pins_blob stays false: the report
        # embeds REDACTED text, so generating one does not extend the life of
        # unredacted material (ADR-0011 R2 §9).
        cited = {f["id"] for f in
                 next(s for s in sections if s["key"] == "findings")["data"]["findings"]}
        for fid in cited:
            for ev in session.execute(select(models.Evidence).where(
                    models.Evidence.finding_id == fid)).scalars().all():
                exists = session.execute(select(models.EvidencePin).where(
                    models.EvidencePin.report_id == report.id,
                    models.EvidencePin.evidence_id == ev.id)).scalar_one_or_none()
                if exists is None:
                    session.add(models.EvidencePin(report_id=report.id, evidence_id=ev.id,
                                                   pins_blob=False))

        for fmt, data, reason in (("html", html_bytes, None), ("json", json_bytes, None),
                                  ("pdf", pdf_bytes, pdf_reason)):
            blob = store.put(session, data, media_type={"html": "text/html",
                                                        "json": "application/json",
                                                        "pdf": "application/pdf"}[fmt]) \
                if data else None
            session.add(models.ReportArtifact(
                report_id=report.id, format=fmt,
                artifact_blob_id=blob.id if blob else None,
                sha256=renderers.sha256(data) if data else "",
                bytes=len(data) if data else 0, unavailable_reason=reason))
        report.state, report.generated_at = "ready", dt.datetime.now(dt.timezone.utc)
    except Exception as exc:                               # noqa: BLE001
        report.state, report.error = "failed", f"{type(exc).__name__}: {exc}"
    audit.record(session, action="report_generated", actor_kind="human", actor_id=p.id,
                 outcome="ok" if report.state == "ready" else "error",
                 subject_type="report", subject_id=str(report.id), trace_id=trace,
                 detail={"state": report.state, "include_states": list(states),
                         "job_ids": ids, "error": report.error})
    session.commit()
    if report.state != "ready":
        raise errors.Problem(500, "report-failed", "Report generation failed", report.error)
    arts = session.execute(select(models.ReportArtifact).where(
        models.ReportArtifact.report_id == report.id)).scalars().all()
    return {"id": str(report.id), "state": report.state, "title": report.title,
            "generated_at": report.generated_at,
            "artifacts": [{"format": a.format, "bytes": a.bytes, "sha256": a.sha256,
                           "unavailable_reason": a.unavailable_reason} for a in arts]}


@router.get("/reports")
def list_reports(asset_id: str | None = None, session: Session = Depends(get_session),
                 p: Principal = Depends(require_role("analyst", "approver"))):
    stmt = select(models.Report).order_by(models.Report.created_at.desc()).limit(50)
    if asset_id:
        stmt = stmt.where(models.Report.asset_id == asset_id)
    rows = session.execute(stmt).scalars().all()
    out = []
    for r in rows:
        arts = session.execute(select(models.ReportArtifact).where(
            models.ReportArtifact.report_id == r.id)).scalars().all()
        out.append({"id": str(r.id), "title": r.title, "state": r.state,
                    "generated_at": r.generated_at, "template_key": r.template_key,
                    "template_version": r.template_version, "filter": r.filter,
                    "artifacts": [{"format": a.format, "bytes": a.bytes,
                                   "unavailable_reason": a.unavailable_reason} for a in arts]})
    return out


@router.get("/reports/{report_id}")
def report_detail(report_id: str, session: Session = Depends(get_session),
                  p: Principal = Depends(require_role("analyst", "approver"))):
    r = session.get(models.Report, report_id)
    if r is None:
        raise errors.not_found("Report")
    sections = session.execute(select(models.ReportSection).where(
        models.ReportSection.report_id == r.id).order_by(
        models.ReportSection.seq)).scalars().all()
    arts = session.execute(select(models.ReportArtifact).where(
        models.ReportArtifact.report_id == r.id)).scalars().all()
    pins = session.execute(select(models.EvidencePin).where(
        models.EvidencePin.report_id == r.id)).scalars().all()
    return {"id": str(r.id), "title": r.title, "state": r.state,
            "generated_at": r.generated_at, "template_key": r.template_key,
            "template_version": r.template_version, "filter": r.filter,
            "job_ids": r.job_ids, "error": r.error,
            "evidence_pinned": len(pins),
            "pins_blob": any(x.pins_blob for x in pins),
            "sections": [{"seq": s.seq, "key": s.key, "heading": s.heading,
                          "body_md": s.body_md, "data": s.data} for s in sections],
            "artifacts": [{"format": a.format, "bytes": a.bytes, "sha256": a.sha256,
                           "unavailable_reason": a.unavailable_reason} for a in arts]}


@router.get("/reports/{report_id}/artifacts/{fmt}")
def download(report_id: str, fmt: str, session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst", "approver")),
             trace: str = Depends(trace_id)):
    r = session.get(models.Report, report_id)
    if r is None:
        raise errors.not_found("Report")
    art = session.execute(select(models.ReportArtifact).where(
        models.ReportArtifact.report_id == r.id,
        models.ReportArtifact.format == fmt)).scalar_one_or_none()
    if art is None:
        raise errors.not_found(f"Artifact {fmt!r}")
    if art.artifact_blob_id is None:
        raise errors.conflict("artifact-unavailable", f"The {fmt} artifact is unavailable",
                              art.unavailable_reason or "the artifact was not produced")
    blob = session.get(models.EvidenceBlob, art.artifact_blob_id)
    data = store.read(blob)
    audit.record(session, action="report_artifact_downloaded", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="report", subject_id=str(r.id), trace_id=trace,
                 detail={"format": fmt, "sha256": art.sha256})
    session.commit()
    media = {"html": "text/html; charset=utf-8", "json": "application/json",
             "pdf": "application/pdf", "md": "text/markdown"}[fmt]
    disposition = "inline" if fmt == "html" else "attachment"
    return Response(content=data, media_type=media, headers={
        "Content-Disposition": f'{disposition}; filename="vapt-report-{report_id[:8]}.{fmt}"',
        "X-Artifact-Sha256": art.sha256})
