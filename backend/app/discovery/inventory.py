"""Build and upsert the attack-surface inventory.

Upserts on natural keys so repeated runs converge instead of duplicating, and
promotes `discovered` -> `verified` when a surface is seen again in a later run
(docs/DATA_FLOW.md step 7).
"""
from __future__ import annotations
import datetime as dt
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from .. import models
from . import classify, extractors


def _upsert_endpoint(session: Session, *, asset_id: Any, run_id: Any, url: str, path: str,
                     method: str, status: int | None, content_type: str | None,
                     evidence_note: str) -> models.Endpoint:
    row = session.execute(select(models.Endpoint).where(
        models.Endpoint.asset_id == asset_id,
        models.Endpoint.url_normalized == url,
        models.Endpoint.method == method)).scalar_one_or_none()
    is_api, api_style = extractors.looks_like_api(path, content_type)
    auth_kind = extractors.classify_auth_entry(path)
    now = dt.datetime.now(dt.timezone.utc)
    if row is None:
        row = models.Endpoint(
            asset_id=asset_id, first_seen_run_id=run_id, last_seen_run_id=run_id,
            url_normalized=url, path=path, method=method, status_code_last=status,
            content_type_last=content_type, is_api=is_api, api_style=api_style,
            requires_auth_guess=(status in (401, 403)), auth_entry_kind=auth_kind,
            assessment="discovered", evidence_note=evidence_note,
            first_seen_at=now, last_seen_at=now)
        session.add(row)
        session.flush()
        return row
    # Seen again in a LATER run: the surface is reproducible -> verified.
    row.assessment = "verified" if row.last_seen_run_id != run_id else row.assessment
    row.last_seen_run_id = run_id
    row.status_code_last = status
    row.content_type_last = content_type
    row.is_api, row.api_style = is_api, api_style
    row.requires_auth_guess = status in (401, 403)
    row.auth_entry_kind = auth_kind
    row.last_seen_at = now
    row.evidence_note = evidence_note
    return row


def _upsert_param(session: Session, endpoint: models.Endpoint, name: str, location: str,
                  assessment: str) -> None:
    row = session.execute(select(models.EndpointParameter).where(
        models.EndpointParameter.endpoint_id == endpoint.id,
        models.EndpointParameter.name == name,
        models.EndpointParameter.location == location)).scalar_one_or_none()
    if row is None:
        session.add(models.EndpointParameter(endpoint_id=endpoint.id, name=name,
                                             location=location, assessment=assessment))
    elif row.assessment == "inferred" and assessment == "discovered":
        row.assessment = "discovered"


def record_response(session: Session, *, asset: models.Asset, run: models.DiscoveryRun,
                    path: str, status: int, headers: dict[str, str], body: str) -> models.Endpoint:
    """Record one response into the inventory. Returns the endpoint row."""
    base = f"{asset.protocol}://{asset.hostname}:{asset.port}"
    url = extractors.normalize_url(base, path) or f"{base}{path}"
    content_type = headers.get("content-type")
    endpoint = _upsert_endpoint(session, asset_id=asset.id, run_id=run.id, url=url,
                                path=path.split("?")[0], method="GET", status=status,
                                content_type=content_type,
                                evidence_note=f"HTTP {status} observed in run {run.id}")

    for name in extractors.query_parameter_names(url):
        _upsert_param(session, endpoint, name, "query", "discovered")

    for header in extractors.SECURITY_HEADERS:
        present = header in headers
        row = session.execute(select(models.ResponseHeader).where(
            models.ResponseHeader.endpoint_id == endpoint.id,
            models.ResponseHeader.header_name == header)).scalar_one_or_none()
        if row is None:
            session.add(models.ResponseHeader(
                endpoint_id=endpoint.id, header_name=header,
                header_value_sample=(headers.get(header) or "")[:400] or None,
                present=present, observed_count=1, assessment="discovered"))
        else:
            row.present, row.observed_count = present, row.observed_count + 1
            row.header_value_sample = (headers.get(header) or "")[:400] or None

    discovered_links: list[str] = []
    if body and "html" in (content_type or ""):
        parsed = extractors.parse_html(body)
        for href in parsed.links:
            nurl = extractors.normalize_url(base, href)
            if nurl and nurl.startswith(base):
                discovered_links.append(nurl)
        for form in parsed.forms:
            action_url = extractors.normalize_url(base, form.action or path) or url
            frow = session.execute(select(models.Form).where(
                models.Form.endpoint_id == endpoint.id,
                models.Form.action_url_normalized == action_url,
                models.Form.method == form.method)).scalar_one_or_none()
            if frow is None:
                frow = models.Form(endpoint_id=endpoint.id, action_url_normalized=action_url,
                                   method=form.method, enctype=form.enctype,
                                   has_csrf_token_field=form.has_csrf_token_field,
                                   is_login_candidate=form.is_login_candidate,
                                   assessment="discovered")
                session.add(frow)
                session.flush()
            for f in form.fields:
                if not f.get("name"):
                    continue
                exists = session.execute(select(models.FormField).where(
                    models.FormField.form_id == frow.id,
                    models.FormField.name == f["name"])).scalar_one_or_none()
                if exists is None:
                    session.add(models.FormField(
                        form_id=frow.id, name=str(f["name"]),
                        input_type=str(f.get("input_type") or ""),
                        is_password=bool(f.get("is_password")),
                        required=bool(f.get("required")),
                        autocomplete=(str(f["autocomplete"]) if f.get("autocomplete") else None)))
            # The form's action is a surface even if never requested: INFERRED.
            action_path = action_url[len(base):].split("?")[0] or "/"
            inferred = _upsert_endpoint(
                session, asset_id=asset.id, run_id=run.id, url=action_url,
                path=action_path, method=form.method, status=None, content_type=None,
                evidence_note=f"inferred from a form on {path} (never requested)")
            if inferred.status_code_last is None:
                inferred.assessment = "inferred"
            for f in form.fields:
                if f.get("name"):
                    _upsert_param(session, inferred, str(f["name"]), "body", "inferred")
    endpoint.evidence_note = (endpoint.evidence_note or "")[:2000]
    session.flush()
    return endpoint


def build_candidates(session: Session, *, asset: models.Asset,
                     run: models.DiscoveryRun) -> int:
    """Deterministic classification over the whole inventory for this asset."""
    endpoints = session.execute(select(models.Endpoint).where(
        models.Endpoint.asset_id == asset.id)).scalars().all()
    written = 0
    for ep in endpoints:
        params = tuple(p.name for p in session.execute(select(models.EndpointParameter).where(
            models.EndpointParameter.endpoint_id == ep.id)).scalars().all())
        forms = session.execute(select(models.Form).where(
            models.Form.endpoint_id == ep.id)).scalars().all()
        fields = []
        for f in forms:
            fields += session.execute(select(models.FormField).where(
                models.FormField.form_id == f.id)).scalars().all()
        missing = tuple(h.header_name for h in session.execute(select(models.ResponseHeader).where(
            models.ResponseHeader.endpoint_id == ep.id,
            models.ResponseHeader.present.is_(False))).scalars().all())
        for cand in classify.candidates_for_endpoint(
                path=ep.path, method=ep.method, is_api=ep.is_api, api_style=ep.api_style,
                auth_entry_kind=ep.auth_entry_kind, parameter_names=params,
                has_login_form=any(f.is_login_candidate for f in forms),
                has_password_field=any(f.is_password for f in fields),
                has_file_input=any((f.input_type or "").lower() == "file" for f in fields),
                missing_security_headers=missing):
            exists = session.execute(select(models.CandidateTest).where(
                models.CandidateTest.asset_id == asset.id,
                models.CandidateTest.endpoint_id == ep.id,
                models.CandidateTest.concern == cand.concern)).scalar_one_or_none()
            if exists is None:
                session.add(models.CandidateTest(
                    asset_id=asset.id, endpoint_id=ep.id, discovery_run_id=run.id,
                    surface_kind=cand.surface_kind, concern=cand.concern,
                    suggested_profile_key=cand.suggested_profile_key,
                    requires_intrusive=cand.requires_intrusive, rationale=cand.rationale,
                    matrix_version=classify.MATRIX_VERSION))
                written += 1
    session.flush()
    return written
