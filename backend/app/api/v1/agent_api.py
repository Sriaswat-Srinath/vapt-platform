"""The advisory agent (L3). It proposes; a human decides; L2 still rules."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import audit, errors, models
from ...agent import runner, tools
from ...agent.boundary import BOUNDARY_VERSION
from ...config import settings
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


@router.get("/agent/capabilities")
def capabilities(p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    s = settings()
    return {
        "llm_enabled": s.llm_enabled,
        "model": s.llm_model if s.llm_enabled else None,
        "provider_host": s.llm_provider_host if s.llm_enabled else None,
        "egress": "CONNECT-only allowlisting proxy; the api has no direct route out",
        "runner_version": runner.RUNNER_VERSION,
        "prompt_version": runner.PROMPT_VERSION,
        "tool_catalogue_version": tools.TOOL_CATALOGUE_VERSION,
        "boundary_version": BOUNDARY_VERSION,
        "tools": tools.catalogue_for_prompt(),
        "cannot": sorted(tools.FORBIDDEN_INTENTS.items()),
        "note": ("The agent is advisory. It proposes from a fixed catalogue, every proposal "
                 "cites stored findings, and accepting one records a human decision rather than "
                 "changing platform state."),
    }


@router.post("/assets/{asset_id}/agent/runs", status_code=201)
def start_run(asset_id: str, session: Session = Depends(get_session),
              p: Principal = Depends(require_role("analyst")),
              trace: str = Depends(trace_id)):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    run = runner.run(session, asset, actor_id=p.id)
    audit.record(session, action="agent_run", actor_kind="human", actor_id=p.id,
                 outcome=run.state, subject_type="asset", subject_id=str(asset.id),
                 trace_id=trace,
                 detail={"run_id": str(run.id), "state": run.state, "error": run.error,
                         "rejected": len(run.rejected or [])})
    session.commit()
    return _run_out(session, run)


def _run_out(session: Session, run: models.AgentRun) -> dict:
    proposals = session.execute(select(models.AgentProposal).where(
        models.AgentProposal.run_id == run.id)).scalars().all()
    return {
        "id": str(run.id), "asset_id": str(run.asset_id), "state": run.state,
        "model": run.model, "provider_host": run.provider_host,
        "runner_version": run.runner_version, "prompt_version": run.prompt_version,
        "tool_catalogue_version": run.tool_catalogue_version,
        "boundary_version": run.boundary_version, "boundary_report": run.boundary_report,
        "bytes_sent": run.bytes_sent, "bytes_received": run.bytes_received,
        "elapsed_ms": run.elapsed_ms, "error": run.error,
        "rejected": run.rejected or [],
        "started_at": run.started_at, "finished_at": run.finished_at,
        "proposals": [_proposal_out(x) for x in proposals],
    }


def _proposal_out(x: models.AgentProposal) -> dict:
    return {"id": str(x.id), "run_id": str(x.run_id), "tool": x.tool,
            "arguments": x.arguments, "citations": list(x.citations or []),
            "state": x.state, "reviewed_by": x.reviewed_by, "reviewed_at": x.reviewed_at,
            "review_note": x.review_note, "created_at": x.created_at,
            "advisory": True}


@router.get("/assets/{asset_id}/agent/runs")
def list_runs(asset_id: str, limit: int = Query(default=20, le=100),
              session: Session = Depends(get_session),
              p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    runs = session.execute(select(models.AgentRun).where(
        models.AgentRun.asset_id == asset_id).order_by(
        models.AgentRun.started_at.desc()).limit(limit)).scalars().all()
    return [_run_out(session, r) for r in runs]


@router.get("/agent/proposals")
def list_proposals(asset_id: str | None = None, state: str | None = None,
                   session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    stmt = select(models.AgentProposal).order_by(models.AgentProposal.created_at.desc())
    if asset_id:
        stmt = stmt.where(models.AgentProposal.asset_id == asset_id)
    if state:
        stmt = stmt.where(models.AgentProposal.state == state)
    return [_proposal_out(x) for x in session.execute(stmt.limit(200)).scalars().all()]


@router.post("/agent/proposals/{proposal_id}/review")
def review(proposal_id: str, decision: str = Query(pattern="^(accepted|rejected)$"),
           note: str | None = Body(default=None, embed=True),
           session: Session = Depends(get_session),
           p: Principal = Depends(require_role("analyst")),
           trace: str = Depends(trace_id)):
    """Record a human's decision about a proposal.

    Accepting changes NO platform state. If the analyst agrees with a mapping
    proposal, they apply it through the analyst-classification endpoint, which
    is a separate, audited, human-actor action — so the audit trail never shows
    a model as the author of a classification.
    """
    row = session.get(models.AgentProposal, proposal_id)
    if row is None:
        raise errors.not_found("Proposal")
    if row.state != "proposed":
        raise errors.conflict("already-reviewed", "This proposal was already reviewed",
                              f"its state is {row.state!r}")
    row.state = decision
    row.reviewed_by = p.id
    row.reviewed_at = dt.datetime.now(dt.timezone.utc)
    row.review_note = note
    audit.record(session, action="agent_proposal_reviewed", actor_kind="human", actor_id=p.id,
                 outcome=decision, subject_type="agent_proposal", subject_id=str(row.id),
                 trace_id=trace, detail={"tool": row.tool, "applied_automatically": False})
    session.commit()
    return _proposal_out(row)
