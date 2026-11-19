"""The conversational analyst: multi-turn Q&A grounded in stored assessment data.

A deliberately MANUAL tool loop rather than the SDK's runner, because every
tool call is validated and executed by the platform before the model sees a
result. The loop is the approval gate; handing it to a helper would hand away
the gate.

What the conversation can do:        ask the platform to read its own data and
                                     explain it, with citations.
What it structurally cannot do:      change anything. The tool catalogue
                                     (agent/retrieval.py) is read-only, so
                                     "could the model start a scan" is not a
                                     question that needs answering — there is
                                     no tool that starts a scan.

Bounded three ways, because a loop that talks to a paid API needs a floor:
  * MAX_TOOL_ROUNDS per question
  * a per-conversation token budget
  * a per-day token budget across the deployment

Every assistant answer is checked for citations: a claim about a finding must
name a handle the model was actually given. An answer that cites nothing is
not rejected — "what is cross-site scripting?" needs no citation — but one
citing a handle it was never given is.
"""
from __future__ import annotations
import dataclasses as dc
import datetime as dt
import json
import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models
from ..config import settings
from . import prompts, retrieval
from .boundary import BoundaryRefusal, enforce

CHAT_VERSION = "1.0.0"
MAX_TOOL_ROUNDS = prompts.MAX_TOOL_ROUNDS
SYSTEM = prompts.CONVERSATION_SYSTEM
HANDLE = re.compile(r"\bf\d{1,3}\b")


class ChatRefused(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dc.dataclass(slots=True)
class Answer:
    text: str
    tool_calls: list[dict[str, Any]]
    citations: list[str]
    refusals: list[dict[str, str]]
    input_tokens: int
    output_tokens: int
    rounds: int
    model: str


def _budget_check(session: Session, conversation: models.Conversation) -> None:
    s = settings()
    spent = int(conversation.input_tokens or 0) + int(conversation.output_tokens or 0)
    if spent >= s.llm_conversation_token_budget:
        raise ChatRefused(
            "conversation budget exhausted",
            f"this conversation has used {spent} tokens of its "
            f"{s.llm_conversation_token_budget} budget. Start a new one.")
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    day = session.execute(
        select(func.coalesce(func.sum(models.Conversation.input_tokens
                                      + models.Conversation.output_tokens), 0))
        .where(models.Conversation.updated_at >= since)).scalar_one()
    if int(day or 0) >= s.llm_daily_token_budget:
        raise ChatRefused(
            "daily budget exhausted",
            f"{int(day)} tokens used in the last 24 hours, limit "
            f"{s.llm_daily_token_budget}. This is a cost control, not a safety control.")


def _history(session: Session, conversation: models.Conversation) -> list[dict[str, Any]]:
    """Prior turns, as the Messages API wants them. Tool traffic is NOT replayed:
    the model gets the conversation, not a transcript of its own lookups."""
    turns = session.execute(select(models.ConversationTurn).where(
        models.ConversationTurn.conversation_id == conversation.id).order_by(
        models.ConversationTurn.created_at)).scalars().all()
    out: list[dict[str, Any]] = []
    for t in turns:
        if t.role in ("user", "assistant") and (t.content or "").strip():
            out.append({"role": t.role, "content": t.content})
    return out[-settings().llm_history_turns:]


def ask(session: Session, conversation: models.Conversation, asset: models.Asset,
        question: str) -> Answer:
    """One question, up to MAX_TOOL_ROUNDS of reading, one grounded answer."""
    from . import client                                   # local: optional path

    s = settings()
    _budget_check(session, conversation)
    if len(question) > s.llm_max_question_chars:
        raise ChatRefused("question too long",
                          f"{len(question)} characters, limit {s.llm_max_question_chars}")

    handles = retrieval.Handles(conversation.handles or {})
    messages: list[dict[str, Any]] = _history(session, conversation)
    messages.append({"role": "user", "content": question})

    # The question is user-supplied text destined for a model: hold it to the
    # same outbound rule as everything else.
    enforce({"question": question})

    tool_calls: list[dict[str, Any]] = []
    refusals: list[dict[str, str]] = []
    in_tokens = out_tokens = 0
    model_name = s.llm_model
    text = ""

    for round_index in range(MAX_TOOL_ROUNDS + 1):
        last_round = round_index == MAX_TOOL_ROUNDS
        response = client.converse(
            system=SYSTEM,
            messages=messages,
            tools=[] if last_round else retrieval.definitions())
        in_tokens += response.input_tokens
        out_tokens += response.output_tokens
        model_name = response.model

        blocks = response.blocks
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        requested = [b for b in blocks if b.get("type") == "tool_use"]
        if not requested:
            break

        messages.append({"role": "assistant", "content": blocks})
        results: list[dict[str, Any]] = []
        for call in requested:
            name, arguments = call.get("name", ""), call.get("input", {}) or {}
            try:
                payload = retrieval.execute(session, asset=asset, handles=handles,
                                            name=name, arguments=arguments)
                # A tool result is outbound data too.
                enforce(payload)
                results.append({"type": "tool_result", "tool_use_id": call.get("id"),
                                "content": json.dumps(payload, default=str)})
                tool_calls.append({"tool": name, "arguments": arguments,
                                   "rows": len(next(iter(payload.values()), []))
                                   if payload else 0})
            except (retrieval.ToolRefused, BoundaryRefusal) as exc:
                reason = getattr(exc, "reason", "refused")
                refusals.append({"tool": name, "reason": reason, "detail": str(exc)})
                results.append({"type": "tool_result", "tool_use_id": call.get("id"),
                                "is_error": True,
                                "content": f"refused ({reason}): {exc}"})
        messages.append({"role": "user", "content": results})

    cited = sorted(set(HANDLE.findall(text)))
    known = set(handles.as_dict())
    invented = [h for h in cited if h not in known]
    if invented:
        refusals.append({"tool": "-", "reason": "invented citation",
                         "detail": f"the answer cited {invented}, which were never supplied"})

    conversation.handles = handles.as_dict()
    conversation.input_tokens = int(conversation.input_tokens or 0) + in_tokens
    conversation.output_tokens = int(conversation.output_tokens or 0) + out_tokens
    conversation.updated_at = dt.datetime.now(dt.timezone.utc)
    return Answer(text=text, tool_calls=tool_calls,
                  citations=[h for h in cited if h in known],
                  refusals=refusals, input_tokens=in_tokens, output_tokens=out_tokens,
                  rounds=round_index, model=model_name)
