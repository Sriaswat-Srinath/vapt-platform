"""Discovery runs and the attack-surface inventory."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ... import audit, errors, models, services
from ...config import settings
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


def _asset_or_404(session: Session, asset_id: str) -> models.Asset:
    a = session.get(models.Asset, asset_id)
    if a is None:
        raise errors.not_found("Asset")
    return a


@router.post("/assets/{asset_id}/discovery-runs", status_code=201)
def start_discovery(asset_id: str, source: str = Query(default="fixture", pattern="^(fixture|live)$"),
                    profile_key: str | None = None,
                    session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("analyst")),
                    trace: str = Depends(trace_id)):
    """Start a discovery run.

    `source=fixture` (default) replays hand-authored synthetic fixtures and makes
    NO network request, so it needs no scan authorisation.
    `source=live` crawls the authorised target and is therefore gated: the API
    evaluates the chain, and the worker re-evaluates it in full — including
    resolve-once-and-pin, which only the worker can perform — before any request.
    """
    asset = _asset_or_404(session, asset_id)
    if source == "live":
        result, decision = services.evaluate_and_persist(
            session, asset=asset, profile_key=profile_key or "zap-passive",
            path=asset.base_path or "/", method="GET", actor_id=p.id,
            subject_type="discovery_run")
        if not result.allowed:
            session.commit()
            raise errors.conflict(
                "scope-denied", "Live discovery denied by scope policy",
                f"Gate {result.first_failure.gate!r} failed",
                {"scope_decision": result.as_dict()})
    run = models.DiscoveryRun(
        asset_id=asset.id, source=source, state="queued",
        profile_key=(profile_key or "zap-passive") if source == "live" else None,
        trace_id=trace, created_by=p.analyst.id,
        scope_grant_id=(services.active_grant(session, asset.id).id
                        if services.active_grant(session, asset.id) else None))
    session.add(run)
    session.flush()
    audit.record(session, action="discovery_requested", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="discovery_run", subject_id=str(run.id),
                 trace_id=trace, detail={"source": source, "profile_key": run.profile_key})
    session.commit()
    # Enqueue. If the broker is unreachable the run stays `queued` and says so.
    try:
        from ...worker.tasks import run_discovery as task
        task.apply_async(args=[str(run.id)], queue="vapt")
        queued = True
    except Exception as exc:                                   # noqa: BLE001
        queued = False
        run.error = f"could not enqueue: {type(exc).__name__}"
        session.commit()
    return {"id": str(run.id), "state": run.state, "source": run.source, "enqueued": queued}


@router.get("/discovery-runs/{run_id}")
def get_run(run_id: str, session: Session = Depends(get_session),
            p: Principal = Depends(require_role("analyst", "approver"))):
    run = session.get(models.DiscoveryRun, run_id)
    if run is None:
        raise errors.not_found("Discovery run")
    return {"id": str(run.id), "asset_id": str(run.asset_id), "source": run.source,
            "state": run.state, "profile_key": run.profile_key, "pages_seen": run.pages_seen,
            "requests_made": run.requests_made, "redirects_blocked": run.redirects_blocked,
            "coverage_complete": run.coverage_complete, "stop_reason": run.stop_reason,
            "error": run.error, "pinned_ips": run.pinned_ips,
            "started_at": run.started_at, "finished_at": run.finished_at}


@router.get("/assets/{asset_id}/discovery-runs")
def list_runs(asset_id: str, session: Session = Depends(get_session),
              p: Principal = Depends(require_role("analyst", "approver"))):
    _asset_or_404(session, asset_id)
    rows = session.execute(select(models.DiscoveryRun).where(
        models.DiscoveryRun.asset_id == asset_id).order_by(
        models.DiscoveryRun.created_at.desc())).scalars().all()
    return [{"id": str(r.id), "source": r.source, "state": r.state, "pages_seen": r.pages_seen,
             "stop_reason": r.stop_reason, "coverage_complete": r.coverage_complete,
             "created_at": r.created_at} for r in rows]


@router.post("/discovery-runs/{run_id}/cancel")
def cancel_run(run_id: str, session: Session = Depends(get_session),
               p: Principal = Depends(require_role("analyst")), trace: str = Depends(trace_id)):
    run = session.get(models.DiscoveryRun, run_id)
    if run is None:
        raise errors.not_found("Discovery run")
    run.cancel_requested_at = dt.datetime.now(dt.timezone.utc)
    audit.record(session, action="discovery_cancel_requested", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="discovery_run", subject_id=str(run.id), trace_id=trace)
    session.commit()
    return {"id": str(run.id), "cancel_requested_at": run.cancel_requested_at,
            "note": "the worker observes cancellation between requests; bounded by "
                    "CANCEL_CHECK_INTERVAL_SECONDS"}


@router.get("/assets/{asset_id}/attack-surface")
def attack_surface(asset_id: str, session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst", "approver"))):
    """Aggregated inventory: the view a stakeholder reads."""
    asset = _asset_or_404(session, asset_id)
    eps = session.execute(select(models.Endpoint).where(
        models.Endpoint.asset_id == asset.id).order_by(models.Endpoint.path)).scalars().all()
    by_assessment: dict[str, int] = {}
    for e in eps:
        by_assessment[e.assessment] = by_assessment.get(e.assessment, 0) + 1
    ep_ids = [e.id for e in eps]
    params = session.execute(select(models.EndpointParameter).where(
        models.EndpointParameter.endpoint_id.in_(ep_ids))).scalars().all() if ep_ids else []
    forms = session.execute(select(models.Form).where(
        models.Form.endpoint_id.in_(ep_ids))).scalars().all() if ep_ids else []
    headers = session.execute(select(models.ResponseHeader).where(
        models.ResponseHeader.endpoint_id.in_(ep_ids))).scalars().all() if ep_ids else []
    cands = session.execute(select(models.CandidateTest).where(
        models.CandidateTest.asset_id == asset.id)).scalars().all()
    return {
        "asset": {"id": str(asset.id), "asset_identifier": asset.asset_identifier,
                  "hostname": asset.hostname, "port": asset.port,
                  "environment": asset.environment},
        "counts": {"endpoints": len(eps), "parameters": len(params), "forms": len(forms),
                   "security_headers_observed": len(headers),
                   "security_headers_missing": sum(1 for h in headers if not h.present),
                   "candidate_tests": len(cands), "api_endpoints": sum(1 for e in eps if e.is_api),
                   "auth_entry_points": sum(1 for e in eps if e.auth_entry_kind != "none")},
        "by_assessment": by_assessment,
        "auth_entry_points": [{"path": e.path, "kind": e.auth_entry_kind, "method": e.method}
                              for e in eps if e.auth_entry_kind != "none"],
        "endpoints": [{"id": str(e.id), "path": e.path, "method": e.method,
                       "status": e.status_code_last, "content_type": e.content_type_last,
                       "is_api": e.is_api, "api_style": e.api_style,
                       "requires_auth_guess": e.requires_auth_guess,
                       "auth_entry_kind": e.auth_entry_kind, "assessment": e.assessment}
                      for e in eps],
    }


@router.get("/endpoints/{endpoint_id}")
def endpoint_detail(endpoint_id: str, session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("analyst", "approver"))):
    ep = session.get(models.Endpoint, endpoint_id)
    if ep is None:
        raise errors.not_found("Endpoint")
    params = session.execute(select(models.EndpointParameter).where(
        models.EndpointParameter.endpoint_id == ep.id)).scalars().all()
    forms = session.execute(select(models.Form).where(
        models.Form.endpoint_id == ep.id)).scalars().all()
    fields = []
    for f in forms:
        fields += [{"form": str(f.id), "name": x.name, "input_type": x.input_type,
                    "is_password": x.is_password, "required": x.required}
                   for x in session.execute(select(models.FormField).where(
                       models.FormField.form_id == f.id)).scalars().all()]
    headers = session.execute(select(models.ResponseHeader).where(
        models.ResponseHeader.endpoint_id == ep.id)).scalars().all()
    return {
        "id": str(ep.id), "url_normalized": ep.url_normalized, "path": ep.path,
        "method": ep.method, "status": ep.status_code_last, "assessment": ep.assessment,
        "evidence_note": ep.evidence_note, "is_api": ep.is_api, "api_style": ep.api_style,
        "auth_entry_kind": ep.auth_entry_kind,
        "parameters": [{"name": x.name, "location": x.location, "assessment": x.assessment}
                       for x in params],
        "forms": [{"id": str(f.id), "action": f.action_url_normalized, "method": f.method,
                   "has_csrf_token_field": f.has_csrf_token_field,
                   "is_login_candidate": f.is_login_candidate} for f in forms],
        "form_fields": fields,
        "security_headers": [{"name": h.header_name, "present": h.present,
                              "value_sample": h.header_value_sample} for h in headers],
    }


@router.get("/assets/{asset_id}/candidate-tests")
def candidate_tests(asset_id: str, session: Session = Depends(get_session),
                    p: Principal = Depends(require_role("analyst", "approver"))):
    """Deterministic test candidates. NOT findings, and not chosen by an LLM."""
    asset = _asset_or_404(session, asset_id)
    rows = session.execute(select(models.CandidateTest).where(
        models.CandidateTest.asset_id == asset.id).order_by(
        models.CandidateTest.concern)).scalars().all()
    out = []
    for c in rows:
        ep = session.get(models.Endpoint, c.endpoint_id) if c.endpoint_id else None
        out.append({"id": str(c.id), "path": ep.path if ep else None,
                    "surface_kind": c.surface_kind, "concern": c.concern,
                    "suggested_profile_key": c.suggested_profile_key,
                    "requires_intrusive": c.requires_intrusive, "rationale": c.rationale,
                    "matrix_version": c.matrix_version})
    return {"matrix_version": rows[0].matrix_version if rows else None,
            "note": ("Deterministic surface->concern mapping. These are candidates, never "
                     "findings; intrusive candidates require an approved profile and genuine "
                     "dual control."),
            "candidates": out}
