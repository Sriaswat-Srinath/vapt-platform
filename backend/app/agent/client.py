"""LLM transport. The ONLY place an outbound model request is made.

Uses the official Anthropic SDK, pointed at the CONNECT-only egress proxy. The
api container has no default route, so there is no path that bypasses the
proxy: if the proxy refuses the destination, the request fails. The worker —
the one component that can reach the scan target — is on no egress network and
never imports this module.

Refusals, in order, before anything leaves:

  1. LLM_ENABLED is false                  -> disabled; nothing is attempted
  2. no API key configured                 -> refused; the SDK is not constructed
  3. the payload has not passed stage 2    -> see agent/boundary.py
  4. the payload exceeds the size cap      -> truncation is the caller's problem
  5. the request exceeds its deadline      -> the run fails; it does not retry forever

Model notes (claude-haiku-4-5, the configured default):
  * `output_config.effort` is NOT supported on Haiku 4.5 and is never sent.
  * Thinking, if enabled, uses `{"type": "enabled", "budget_tokens": N}` — the
    adaptive form belongs to the Opus/Sonnet generations.
  * 200K context, which the per-tool prompts (agent/prompts.py) stay far inside.
"""
from __future__ import annotations
import dataclasses as dc
import json
import time
from typing import Any

from ..config import settings
from .boundary import BoundaryRefusal, enforce

CLIENT_VERSION = "2.0.0"
MAX_PAYLOAD_BYTES = 256 * 1024

# Only this schema is accepted back. Declared here rather than in the prompt
# alone so the provider constrains generation where it can, and the platform's
# validator (agent/tools.py) still refuses anything that slips through.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "arguments": {"type": "object"},
                    "citations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["tool", "arguments"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["proposals"],
    "additionalProperties": False,
}


class LlmDisabled(RuntimeError):
    """LLM_ENABLED is false. The default, and not an error condition."""


class LlmRefused(RuntimeError):
    """The request was not made, or did not complete. Carries why."""


@dc.dataclass(frozen=True, slots=True)
class LlmResponse:
    text: str
    input_tokens: int
    output_tokens: int
    elapsed_ms: int
    provider_host: str
    model: str
    structured: bool
    stop_reason: str | None

    @property
    def bytes_received(self) -> int:
        return len(self.text.encode())


def _build_client():
    """Construct the SDK client. Raises LlmRefused rather than returning None."""
    s = settings()
    if not s.anthropic_api_key:
        raise LlmRefused(
            "no provider API key is configured (ANTHROPIC_API_KEY). The agent is advisory and "
            "off by default; a key is a deliberate, separate decision.")
    try:
        import anthropic
        from anthropic import DefaultHttpxClient
    except ImportError as exc:                              # pragma: no cover
        raise LlmRefused(f"the anthropic SDK is not installed in this image: {exc}") from exc

    kwargs: dict[str, Any] = {
        "api_key": s.anthropic_api_key,
        "timeout": float(s.llm_timeout_seconds),
        "max_retries": s.llm_max_retries,
    }
    if s.llm_base_url:
        # Used for the local test stand-in, which speaks the Messages API shape
        # over plain HTTP. The real provider uses the SDK default (HTTPS).
        kwargs["base_url"] = s.llm_base_url
    if s.llm_proxy_url:
        # Every byte leaves through the CONNECT-only allowlisting proxy, which
        # tunnels TLS it cannot read. `verify` names the TEST stand-in's trust
        # anchor when one is configured; a real provider uses the system store.
        http_kwargs: dict[str, Any] = {"proxy": s.llm_proxy_url}
        if s.llm_ca_bundle:
            http_kwargs["verify"] = s.llm_ca_bundle
        kwargs["http_client"] = DefaultHttpxClient(**http_kwargs)
    return anthropic.Anthropic(**kwargs)


def _request_kwargs(system: str, user_content: dict, *, structured: bool) -> dict[str, Any]:
    s = settings()
    kwargs: dict[str, Any] = {
        "model": s.llm_model,
        "max_tokens": s.llm_max_output_tokens,
        "system": system,
        "messages": [{"role": "user", "content": json.dumps(user_content, separators=(",", ":"))}],
    }
    # Haiku 4.5 takes an explicit thinking budget; it has no effort setting, and
    # sending `output_config.effort` to it is an error.
    if s.llm_thinking_budget_tokens:
        kwargs["thinking"] = {"type": "enabled",
                              "budget_tokens": s.llm_thinking_budget_tokens}
    if structured:
        kwargs["output_config"] = {"format": {"type": "json_schema",
                                              "schema": RESPONSE_SCHEMA}}
    return kwargs


def send(system: str, user_content: dict, *, timeout_s: float | None = None) -> LlmResponse:
    """One request. `user_content` MUST be an object the boundary has passed."""
    s = settings()
    if not s.llm_enabled:
        raise LlmDisabled("LLM_ENABLED is false")

    checked, _report = enforce(user_content)          # refuses rather than sends
    body = json.dumps(checked, separators=(",", ":")).encode()
    if len(body) > MAX_PAYLOAD_BYTES:
        raise LlmRefused(f"payload is {len(body)} bytes, over the {MAX_PAYLOAD_BYTES} cap")
    # The system prompt is ours, but it is cheap to hold it to the same rule.
    enforce({"system": system})

    client = _build_client()
    started = time.monotonic()
    structured = s.llm_structured_output
    try:
        try:
            response = client.messages.create(**_request_kwargs(system, checked,
                                                                structured=structured))
        except Exception as exc:                            # noqa: BLE001
            # A provider that rejects the structured-output parameter must not
            # take the whole feature down: retry once in plain mode and record
            # which mode answered, rather than silently degrading.
            if structured and "output_config" in str(exc):
                structured = False
                response = client.messages.create(**_request_kwargs(system, checked,
                                                                    structured=False))
            else:
                raise
    except Exception as exc:                                # noqa: BLE001
        raise LlmRefused(f"{type(exc).__name__}: {exc}") from exc

    elapsed = int((time.monotonic() - started) * 1000)
    text = "".join(block.text for block in response.content
                   if getattr(block, "type", None) == "text")
    usage = getattr(response, "usage", None)
    return LlmResponse(
        text=text,
        input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
        output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        elapsed_ms=elapsed,
        provider_host=(s.llm_base_url or "api.anthropic.com"),
        model=getattr(response, "model", s.llm_model),
        structured=structured,
        stop_reason=getattr(response, "stop_reason", None))


@dc.dataclass(frozen=True, slots=True)
class ConverseResponse:
    """A multi-turn reply, with its content blocks intact so a tool loop can
    replay them. The caller owns the loop (agent/chat.py)."""
    blocks: list[dict[str, Any]]
    input_tokens: int
    output_tokens: int
    model: str
    stop_reason: str | None


def converse(*, system: str, messages: list[dict[str, Any]],
             tools: list[dict[str, Any]] | None = None) -> ConverseResponse:
    """One turn of a conversation, optionally offering READ-ONLY tools.

    The boundary has already seen the question and every tool result the caller
    put into `messages`; this function does not re-walk the whole history on
    each turn, because the only new material is what the caller just enforced.
    """
    s = settings()
    if not s.llm_enabled:
        raise LlmDisabled("LLM_ENABLED is false")
    client = _build_client()
    kwargs: dict[str, Any] = {
        "model": s.llm_model,
        "max_tokens": s.llm_max_output_tokens,
        "system": system,
        "messages": messages,
    }
    if tools:
        kwargs["tools"] = tools
    if s.llm_thinking_budget_tokens:
        kwargs["thinking"] = {"type": "enabled",
                              "budget_tokens": s.llm_thinking_budget_tokens}
    try:
        response = client.messages.create(**kwargs)
    except Exception as exc:                                # noqa: BLE001
        raise LlmRefused(f"{type(exc).__name__}: {exc}") from exc

    blocks: list[dict[str, Any]] = []
    for block in response.content:
        kind = getattr(block, "type", None)
        if kind == "text":
            blocks.append({"type": "text", "text": block.text})
        elif kind == "tool_use":
            blocks.append({"type": "tool_use", "id": block.id, "name": block.name,
                           "input": dict(block.input or {})})
    usage = getattr(response, "usage", None)
    return ConverseResponse(
        blocks=blocks,
        input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
        output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        model=getattr(response, "model", s.llm_model),
        stop_reason=getattr(response, "stop_reason", None))


__all__ = ["send", "converse", "LlmDisabled", "LlmRefused", "LlmResponse",
           "ConverseResponse", "BoundaryRefusal", "CLIENT_VERSION", "RESPONSE_SCHEMA"]
