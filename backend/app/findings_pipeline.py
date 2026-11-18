"""Raw observations -> findings + evidence + validation + CVSS.

Each stage is separable and idempotent so it can be re-run over unchanged
hashed inputs: normalisation is pure, dedup is keyed on the fingerprint, and
validation records a new event only when the state actually changes.
"""
from __future__ import annotations
import datetime as dt
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from . import audit, models
from .discovery import extractors
from .evidence import redaction, store
from .normalization import mapper
from .normalization import zap_mapping as zm
from .validation import engine as ve
from .risk import cvss

SECURITY_HEADER_FOR_KEY = {
    "missing-security-header-csp": "content-security-policy",
    "missing-security-header-frame-options": "x-frame-options",
    "missing-security-header-content-type-options": "x-content-type-options",
    "missing-security-header-hsts": "strict-transport-security",
    "missing-security-header-permissions-policy": "permissions-policy",
}


def _split_http(text: str | None) -> tuple[dict[str, str], str]:
    """Split a raw HTTP message into lowercase headers and a body."""
    if not text:
        return {}, ""
    head, _, body = text.partition("\r\n\r\n")
    if not _:
        head, _, body = text.partition("\n\n")
    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:
        if ":" in line:
            k, _sep, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers, body


def _store_evidence(session: Session, finding: models.Finding, *, kind: str, label: str,
                    text: str, raw_observation_id: Any, media_type: str | None) -> models.Evidence:
    """Redact on write; keep the unredacted original in the blob store."""
    redacted, report = redaction.redact(text)
    blob = store.put(session, text.encode("utf-8", "replace"), media_type=media_type)
    existing = session.execute(select(models.Evidence).where(
        models.Evidence.finding_id == finding.id, models.Evidence.kind == kind,
        models.Evidence.content_sha256 == blob.content_sha256)).scalar_one_or_none()
    if existing is not None:
        return existing
    row = models.Evidence(
        finding_id=finding.id, raw_observation_id=raw_observation_id, blob_id=blob.id,
        kind=kind, label=label, content_redacted=redacted,
        content_sha256=blob.content_sha256, redacted_sha256=redaction.sha256(redacted),
        redaction_version=report.version, redaction_report=report.as_dict(),
        media_type=media_type, collected_by="system")
    session.add(row)
    session.flush()
    return row


def _validation_inputs(*, nf: mapper.NormalizedFinding, coverage_complete: bool,
                       req_headers: dict[str, str], req_body: str,
                       resp_headers: dict[str, str], resp_body: str,
                       has_request: bool, has_response: bool,
                       transport_is_cleartext: bool = False) -> ve.ValidationInputs:
    header = SECURITY_HEADER_FOR_KEY.get(nf.catalogue_key or "")
    present = absent = 0
    if header and has_response:
        if header in resp_headers:
            present = 1
        else:
            absent = 1
    status = 0
    evidence = nf.scanner_evidence
    found = bool(evidence) and bool(resp_body) and (evidence or "") in resp_body
    content_type = resp_headers.get("content-type", "")
    html = "html" in content_type.lower()
    unencoded = bool(evidence) and found and not any(
        tok in resp_body for tok in (f"&lt;{evidence}", f"&amp;{evidence}")) and (
        "<" in (evidence or "") or html)
    # Cookie facts for the session-management pack. The Set-Cookie VALUE is
    # never read: only whether a cookie was set and which attribute names it
    # carries.
    set_cookie = resp_headers.get("set-cookie") if has_response else None
    cookie_attrs = extractors.cookie_attributes(set_cookie)
    claimed = zm.cookie_attribute_claim(nf.adapter_rule_id)
    # Which header claims are BROWSER POLICY (and so meaningless on a JSON
    # response) and which apply to any response at all.
    browser_policy = (nf.catalogue_key or "").startswith("missing-security-header") or \
        (nf.catalogue_key or "") == "cache-control-directives"
    return ve.ValidationInputs(
        evidence_class=nf.evidence_class, coverage_complete=coverage_complete,
        status_codes=(status,) if status else (),
        content_types=(content_type,) if content_type else (),
        distinct_urls=1 if has_response else 0,
        response_count=1 if has_response else 0,
        header_present_count=present, header_absent_count=absent,
        scanner_evidence=evidence, evidence_found_in_body=found,
        reflected_unencoded=unencoded, html_context=html,
        has_request_evidence=has_request, has_response_evidence=has_response,
        confidence=nf.confidence,
        set_cookie_count=1 if set_cookie else 0,
        cookie_attributes_present=cookie_attrs,
        cookie_attribute_claimed_missing=claimed,
        transport_is_cleartext=transport_is_cleartext,
        claim_is_browser_policy=browser_policy)


def _attach_cvss(session: Session, finding: models.Finding) -> models.RiskScore | None:
    entry = session.execute(select(models.VulnCatalogue).where(
        models.VulnCatalogue.key == finding.catalogue_key)).scalar_one_or_none() \
        if finding.catalogue_key else None
    att = (cvss.attach_from_catalogue(version=entry.cvss_version, vector=entry.cvss_vector,
                                      base=float(entry.cvss_base) if entry.cvss_base else None)
           if entry else cvss.CvssAttachment(None, None, None, None, False,
                                             "no catalogue entry for this detection"))
    row = models.RiskScore(
        finding_id=finding.id, cvss_source=att.source, cvss_version=att.version,
        cvss_vector=att.vector, cvss_base=att.base,
        epss_score=None, epss_asof=None, kev_listed=False,
        # The MVP computes no prioritisation score: null, not a premature number.
        priority_score=None, priority_band=None, formula_version=None,
        inputs={"cvss_reason": att.reason, "catalogue_key": finding.catalogue_key,
                "severity": finding.severity, "confidence": finding.confidence,
                "epss": None, "kev": None,
                "note": "priority scoring is deferred in the MVP; CVSS is stored separately"})
    session.add(row)
    session.flush()
    return row


def process_job(session: Session, job: models.ScanJob, asset: models.Asset) -> dict[str, int]:
    """Normalise, dedup, store evidence, validate and attach CVSS."""
    observations = session.execute(select(models.RawObservation).where(
        models.RawObservation.job_id == job.id).order_by(
        models.RawObservation.captured_at)).scalars().all()
    stats = {"observations": len(observations), "findings_new": 0, "findings_updated": 0,
             "unmapped": 0, "evidence": 0, "confirmed": 0, "false_positive": 0,
             "inconclusive": 0, "not_applicable": 0, "candidate": 0}
    for obs in observations:
        nf = mapper.normalize_zap_alert(
            asset_id=str(asset.id), payload=obs.payload or {},
            adapter_rule_id=obs.adapter_rule_id, observed_url=obs.observed_url,
            detection_source="zap_passive" if obs.adapter_name == "zap" else "mock")
        if nf is None:
            continue
        if nf.unmapped:
            stats["unmapped"] += 1
        finding = session.execute(select(models.Finding).where(
            models.Finding.asset_id == asset.id,
            models.Finding.fingerprint == nf.fingerprint)).scalar_one_or_none()
        now = dt.datetime.now(dt.timezone.utc)
        if finding is None:
            finding = models.Finding(
                asset_id=asset.id, job_id=job.id, catalogue_key=nf.catalogue_key,
                fingerprint=nf.fingerprint, title=nf.title, category=nf.category,
                affected_url=nf.affected_url, http_method=nf.http_method,
                parameter_name=nf.parameter_name, severity=nf.severity,
                confidence=nf.confidence, description_md=nf.description_md,
                detection_source=nf.detection_source, validation_state="candidate",
                coverage_complete=bool(job.coverage_complete),
                unmapped_rule_id=nf.adapter_rule_id if nf.unmapped else None,
                first_seen_at=now, last_seen_at=now)
            session.add(finding)
            session.flush()
            stats["findings_new"] += 1
        else:
            finding.occurrence_count += 1
            finding.last_seen_at = now
            finding.job_id = job.id
            finding.coverage_complete = bool(job.coverage_complete)
            stats["findings_updated"] += 1
        link = session.get(models.FindingObservation, (finding.id, obs.id))
        if link is None:
            session.add(models.FindingObservation(finding_id=finding.id,
                                                  raw_observation_id=obs.id))
        # ---- evidence, redacted on write --------------------------------
        req_text = resp_text = None
        if obs.request_blob_id:
            blob = session.get(models.EvidenceBlob, obs.request_blob_id)
            if blob and blob.state == "present":
                try:
                    req_text = store.read(blob).decode("utf-8", "replace")
                except (FileNotFoundError, ValueError):
                    req_text = None
        if obs.response_blob_id:
            blob = session.get(models.EvidenceBlob, obs.response_blob_id)
            if blob and blob.state == "present":
                try:
                    resp_text = store.read(blob).decode("utf-8", "replace")
                except (FileNotFoundError, ValueError):
                    resp_text = None
        req_headers, req_body = _split_http(req_text)
        resp_headers, resp_body = _split_http(resp_text)
        if req_text:
            _store_evidence(session, finding, kind="http_request", label="scanner request",
                            text=req_text, raw_observation_id=obs.id, media_type="message/http")
            stats["evidence"] += 1
        if resp_text:
            _store_evidence(session, finding, kind="http_response", label="scanner response",
                            text=resp_text, raw_observation_id=obs.id, media_type="message/http")
            stats["evidence"] += 1
        # ---- deterministic validation -----------------------------------
        outcome = ve.classify(_validation_inputs(
            nf=nf, coverage_complete=bool(job.coverage_complete),
            req_headers=req_headers, req_body=req_body,
            resp_headers=resp_headers, resp_body=resp_body,
            has_request=bool(req_text), has_response=bool(resp_text),
            transport_is_cleartext=(asset.protocol or "http").lower() == "http"))
        evidence_ids = [str(e.id) for e in session.execute(select(models.Evidence).where(
            models.Evidence.finding_id == finding.id)).scalars().all()]
        if finding.validation_state != outcome.state or finding.validation_rule_id != outcome.rule_id:
            session.add(models.ValidationEvent(
                finding_id=finding.id, from_state=finding.validation_state,
                to_state=outcome.state, rule_id=outcome.rule_id,
                rule_version=outcome.rule_version, rule_inputs=outcome.as_dict()["inputs"],
                evidence_ids=evidence_ids, actor_kind="system", actor_id="validation_engine",
                note=outcome.reason))
            finding.validation_state = outcome.state
            finding.validation_rule_id = outcome.rule_id
            finding.validation_version = outcome.rule_version
        stats[outcome.state] = stats.get(outcome.state, 0) + 1
        # ---- CVSS from the catalogue ------------------------------------
        if not session.execute(select(models.RiskScore).where(
                models.RiskScore.finding_id == finding.id)).scalars().first():
            _attach_cvss(session, finding)
        entry = session.execute(select(models.VulnCatalogue).where(
            models.VulnCatalogue.key == finding.catalogue_key)).scalar_one_or_none() \
            if finding.catalogue_key else None
        if entry is not None and not finding.remediation_md:
            finding.remediation_md = entry.remediation_md
        session.flush()
    audit.record(session, action="findings_processed", actor_kind="system",
                 actor_id="validation_engine", outcome="ok", subject_type="scan_job",
                 subject_id=str(job.id), detail=stats)
    session.commit()
    return stats
