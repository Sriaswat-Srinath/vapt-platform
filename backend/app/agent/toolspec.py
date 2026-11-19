"""The READ-ONLY tool catalogue: schemas, validation and handles.

Dependency-free on purpose. The executors live in `retrieval.py`, which needs
the ORM; everything that DECIDES whether a call is permitted lives here, so it
can be imported and tested without a database, a container or a network.

This is the one place where a model gets to ask the platform for data it was
not handed up front, so the rules are tighter than anywhere else in the agent:

  * Every tool READS. There is no mutating tool, so there is no "can it change
    anything" question to get wrong — the capability simply does not exist.
  * Every call is scoped to the conversation's ONE asset, server-side. The
    model cannot name an asset, and an asset id never appears in a tool
    argument.
  * Every argument is validated against a fixed schema before execution.
    Unknown tool, unknown argument or out-of-range value -> refused and
    recorded, never guessed at.
  * Findings are returned as HANDLES (f1, f2 …) that are stable within one
    conversation. The platform's identifiers never reach the model.
  * Every result passes the stage-2 boundary before it is handed back, so a
    tool cannot become a way to read unredacted evidence.

A refusal is recorded on the turn rather than hidden, because a model reaching
for something it cannot have is the behaviour most worth seeing.
"""
from __future__ import annotations
import dataclasses as dc
from typing import Any

from .. import taxonomy as tax

RETRIEVAL_VERSION = "1.0.0"
MAX_ROWS = 50

VALIDATION_STATES = ("confirmed", "candidate", "false_positive", "inconclusive",
                     "not_applicable")
SEVERITIES = ("critical", "high", "medium", "low", "informational")


class ToolRefused(ValueError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dc.dataclass(frozen=True, slots=True)
class ReadTool:
    name: str
    description: str
    schema: dict[str, Any]


TOOLS: tuple[ReadTool, ...] = (
    ReadTool("list_findings",
             "List findings for the assessed application. Returns handles, titles, "
             "categories, validation states and severities — not full evidence.",
             {"type": "object", "properties": {
                 "validation_state": {"type": "string", "enum": list(VALIDATION_STATES)},
                 "category": {"type": "string", "enum": [c.key for c in tax.ALL]},
                 "severity": {"type": "string", "enum": list(SEVERITIES)},
                 "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
             }, "additionalProperties": False}),
    ReadTool("get_finding",
             "Full detail for ONE finding by handle: provenance, the deterministic "
             "rule that set its state, CVSS, and REDACTED evidence excerpts.",
             {"type": "object", "properties": {
                 "handle": {"type": "string"},
             }, "required": ["handle"], "additionalProperties": False}),
    ReadTool("get_coverage",
             "What this build could have found, per vulnerability category, including "
             "the categories it cannot detect at all.",
             {"type": "object", "properties": {}, "additionalProperties": False}),
    ReadTool("list_assessments",
             "Recent assessments: mode (fixture or live), profile, state, and whether "
             "coverage was complete.",
             {"type": "object", "properties": {
                 "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
             }, "additionalProperties": False}),
    ReadTool("list_candidate_tests",
             "Deterministically-produced candidate tests: surfaces worth examining. "
             "These are NOT findings.",
             {"type": "object", "properties": {
                 "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
             }, "additionalProperties": False}),
    ReadTool("list_reports",
             "Reports generated for this application, with their artifact formats.",
             {"type": "object", "properties": {
                 "limit": {"type": "integer", "minimum": 1, "maximum": 20},
             }, "additionalProperties": False}),
    ReadTool("get_scope_and_authorisation",
             "The authorisation state and scope rules that govern what may be assessed, "
             "and why an assessment would currently be allowed or denied.",
             {"type": "object", "properties": {}, "additionalProperties": False}),
)
BY_NAME = {t.name: t for t in TOOLS}


def definitions() -> list[dict[str, Any]]:
    """Tool definitions in the shape the Messages API expects."""
    return [{"name": t.name, "description": t.description, "input_schema": t.schema}
            for t in TOOLS]


def _validate(name: str, arguments: dict) -> dict:
    tool = BY_NAME.get(name)
    if tool is None:
        raise ToolRefused("unknown tool", f"{name!r} is not a readable tool")
    if not isinstance(arguments, dict):
        raise ToolRefused("malformed", f"{name}: arguments must be an object")
    props = tool.schema["properties"]
    extra = [k for k in arguments if k not in props]
    if extra:
        raise ToolRefused("unexpected argument", f"{name}: {extra}")
    for key in tool.schema.get("required", []):
        if key not in arguments:
            raise ToolRefused("incomplete", f"{name}: missing {key!r}")
    clean: dict[str, Any] = {}
    for key, value in arguments.items():
        spec = props[key]
        if spec.get("enum") and value not in spec["enum"]:
            raise ToolRefused("invalid value",
                              f"{name}.{key}={value!r} is not one of {spec['enum']}")
        if spec.get("type") == "integer":
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ToolRefused("invalid value", f"{name}.{key} must be an integer") from exc
            value = max(spec.get("minimum", 1), min(spec.get("maximum", MAX_ROWS), value))
        clean[key] = value
    return clean


class Handles:
    """Finding handles, stable for the life of ONE conversation.

    The model only ever sees `f1`, `f2`, …; the mapping lives here and is
    rebuilt from the conversation's stored turns, so it survives restarts
    without the identifiers ever being sent.
    """

    def __init__(self, existing: dict[str, str] | None = None) -> None:
        self._to_id: dict[str, str] = dict(existing or {})
        self._to_handle = {v: k for k, v in self._to_id.items()}

    def handle_for(self, finding_id: str) -> str:
        if finding_id in self._to_handle:
            return self._to_handle[finding_id]
        handle = f"f{len(self._to_id) + 1}"
        self._to_id[handle] = finding_id
        self._to_handle[finding_id] = handle
        return handle

    def id_for(self, handle: str) -> str:
        if handle not in self._to_id:
            raise ToolRefused("unknown handle",
                              f"{handle!r} was never given to you in this conversation")
        return self._to_id[handle]

    def as_dict(self) -> dict[str, str]:
        return dict(self._to_id)
