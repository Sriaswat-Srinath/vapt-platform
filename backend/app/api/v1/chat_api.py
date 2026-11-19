"""The conversational analyst. Read-only, cited, and bound to one asset."""
from __future__ import annotations
import datetime as dt
from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from ... import audit, errors, models
from ...agent import chat, client, retrieval
from ...agent.boundary import BoundaryRefusal
from ...config import settings
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


@router.get("/chat/capabilities")
def capabilities(p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    s = settings()
    return {
        "enabled": s.llm_enabled,
        "model": s.llm_model if s.llm_enabled else None,
        "chat_version": chat.CHAT_VERSION,
        "retrieval_version": retrieval.RETRIEVAL_VERSION,
        "max_tool_rounds": chat.MAX_TOOL_ROUNDS,
        "conversation_token_budget": s.llm_conversation_token_budget,
        "tools": [{"name": t.name, "description": t.description} for t in retrieval.TOOLS],
        "note": ("Every tool READS. There is no tool that starts, stops or changes an "
                 "assessment, so the assistant cannot act on the platform — only describe it. "
                 "Claims about findings cite handles the analyst can check."),
    }


def _conversation(session: Session, conversation_id: str, p: Principal) -> models.Conversation:
    row = session.get(models.Conversation, conversation_id)
    if row is None:
        raise errors.not_found("Conversation")
    if str(row.analyst_id) != str(p.analyst.id) and p.analyst.role != "admin":
        raise errors.forbidden("a conversation belongs to the analyst who started it")
    return row


def _turn_out(t: models.ConversationTurn) -> dict:
    return {"id": str(t.id), "role": t.role, "content": t.content,
            "citations": list(t.citations or []), "tool_calls": t.tool_calls or [],
            "refusals": t.refusals or [], "rounds": t.rounds, "model": t.model,
            "input_tokens": t.input_tokens, "output_tokens": t.output_tokens,
            "error": t.error, "created_at": t.created_at}


def _conversation_out(session: Session, c: models.Conversation) -> dict:
    turns = session.execute(select(models.ConversationTurn).where(
        models.ConversationTurn.conversation_id == c.id).order_by(
        models.ConversationTurn.created_at)).scalars().all()
    return {"id": str(c.id), "asset_id": str(c.asset_id), "title": c.title,
            "state": c.state, "input_tokens": c.input_tokens,
            "output_tokens": c.output_tokens, "created_at": c.created_at,
            "updated_at": c.updated_at, "turns": [_turn_out(t) for t in turns]}


@router.post("/assets/{asset_id}/conversations", status_code=201)
def start(asset_id: str, title: str | None = Body(default=None, embed=True),
          session: Session = Depends(get_session),
          p: Principal = Depends(require_role("analyst", "approver")),
          trace: str = Depends(trace_id)):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    row = models.Conversation(asset_id=asset.id, analyst_id=p.analyst.id,
                              title=title or f"Assessment of {asset.asset_identifier}")
    session.add(row)
    session.flush()
    audit.record(session, action="conversation_started", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="conversation", subject_id=str(row.id),
                 trace_id=trace, detail={"asset": asset.asset_identifier})
    session.commit()
    return _conversation_out(session, row)


@router.get("/conversations")
def list_conversations(asset_id: str | None = None, limit: int = Query(default=20, le=100),
                       session: Session = Depends(get_session),
                       p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    stmt = select(models.Conversation).order_by(models.Conversation.updated_at.desc())
    if asset_id:
        stmt = stmt.where(models.Conversation.asset_id == asset_id)
    if p.analyst.role != "admin":
        stmt = stmt.where(models.Conversation.analyst_id == p.analyst.id)
    rows = session.execute(stmt.limit(limit)).scalars().all()
    return [{"id": str(c.id), "asset_id": str(c.asset_id), "title": c.title,
             "state": c.state, "input_tokens": c.input_tokens,
             "output_tokens": c.output_tokens, "updated_at": c.updated_at} for c in rows]


@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, session: Session = Depends(get_session),
                     p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    return _conversation_out(session, _conversation(session, conversation_id, p))


@router.post("/conversations/{conversation_id}/messages", status_code=201)
def ask(conversation_id: str, question: str = Body(..., embed=True),
        session: Session = Depends(get_session),
        p: Principal = Depends(require_role("analyst", "approver")),
        trace: str = Depends(trace_id)):
    """Ask a question. The assistant may READ platform data; it changes nothing."""
    conversation = _conversation(session, conversation_id, p)
    asset = session.get(models.Asset, conversation.asset_id)
    session.add(models.ConversationTurn(conversation_id=conversation.id, role="user",
                                        content=question))
    session.flush()

    error = None
    answer = None
    try:
        answer = chat.ask(session, conversation, asset, question)
    except client.LlmDisabled as exc:
        error = (f"{exc}. The assistant is advisory and off by default; enabling it changes "
                 "nothing about what the platform will execute.")
    except (chat.ChatRefused, client.LlmRefused, BoundaryRefusal) as exc:
        error = str(exc)

    turn = models.ConversationTurn(
        conversation_id=conversation.id, role="assistant",
        content=(answer.text if answer else ""),
        citations=(answer.citations if answer else None),
        tool_calls=(answer.tool_calls if answer else None),
        refusals=(answer.refusals if answer else None),
        input_tokens=(answer.input_tokens if answer else None),
        output_tokens=(answer.output_tokens if answer else None),
        rounds=(answer.rounds if answer else None),
        model=(answer.model if answer else None),
        error=error)
    session.add(turn)
    conversation.updated_at = dt.datetime.now(dt.timezone.utc)
    audit.record(session, action="conversation_question", actor_kind="human", actor_id=p.id,
                 outcome="error" if error else "ok", subject_type="conversation",
                 subject_id=str(conversation.id), trace_id=trace,
                 detail={"tools_used": [t["tool"] for t in (answer.tool_calls if answer else [])],
                         "refusals": len(answer.refusals) if answer else 0,
                         "error": error})
    session.commit()
    return _turn_out(turn)
