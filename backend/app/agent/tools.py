"""The fixed, allowlisted catalogue of things the agent may PROPOSE.

The model does not act. It returns proposals drawn from this catalogue, and a
proposal is a row a human reads and accepts or rejects. Nothing here mutates a
validation state, a severity, a CVSS score, a scope rule, a rate limit or a
job: those belong to L2 (CLAUDE.md rule 13).

A proposal naming a tool that is not here is REJECTED and recorded as a
refusal. A proposal that cites a finding the asset does not have is rejected
too — an uncited claim is indistinguishable from an invented one.
"""
from __future__ import annotations
import dataclasses as dc

from .. import taxonomy as tax

TOOL_CATALOGUE_VERSION = "1.0.0"


@dc.dataclass(frozen=True, slots=True)
class Tool:
    name: str
    summary: str
    requires_citations: bool
    # Fields the model must supply, and nothing else is accepted.
    fields: tuple[str, ...]
    # What accepting this proposal does in the platform. "nothing" means the
    # acceptance is recorded and a human acts; it is never applied automatically.
    on_accept: str


TOOLS: tuple[Tool, ...] = (
    Tool("explain_finding",
         "Explain one stored finding in plain language for a report reader, using only the "
         "redacted evidence provided.",
         True, ("finding_id", "explanation", "confidence_note"), "nothing"),
    Tool("suggest_remediation",
         "Draft remediation wording for a finding. The curated catalogue's text remains "
         "authoritative; this is an alternative phrasing a human may choose.",
         True, ("finding_id", "remediation"), "nothing"),
    Tool("map_unmapped_detection",
         "Propose which taxonomy category an unmapped detection belongs to. A human applies it "
         "through the analyst-classification endpoint, which is audited.",
         True, ("finding_id", "taxonomy_key", "reasoning"), "nothing"),
    Tool("prioritise_candidate_tests",
         "Rank the deterministically-produced candidate tests for analyst attention. The ranking "
         "is advisory; it cannot add a candidate, change intrusiveness or start anything.",
         False, ("ordering", "reasoning"), "nothing"),
    Tool("summarise_coverage_gap",
         "Describe, for a report reader, what a Tier-1 category's lack of coverage means and "
         "what evidence would be needed to close it.",
         False, ("taxonomy_key", "summary", "what_would_close_it"), "nothing"),
    Tool("flag_for_human_review",
         "Raise something the analyst should look at that no rule covers — typically a business "
         "logic surface. Explicitly not a finding.",
         False, ("subject", "why", "taxonomy_key"), "nothing"),
)
BY_NAME = {t.name: t for t in TOOLS}

# Things the model is structurally unable to do. Listed so the refusal message
# can name the rule rather than say "invalid".
FORBIDDEN_INTENTS = {
    "set_validation_state": "validation state is set by deterministic rule packs only",
    "set_severity": "severity comes from the scanner and the curated catalogue",
    "set_cvss": "CVSS comes from the curated catalogue only",
    "start_assessment": "only a human starts an assessment, and the gate chain admits it",
    "change_scope": "scope is human-authorised and gate-enforced",
    "enable_scanner": "safety flags are configuration, not a model output",
    "run_command": "the agent has no execution capability of any kind",
}


class ProposalRejected(ValueError):
    """A model output that the platform refuses to store as a proposal."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def validate(proposal: dict, *, known_finding_ids: set[str]) -> dict:
    """Total: returns a normalised proposal or raises. Never partially accepts."""
    if not isinstance(proposal, dict):
        raise ProposalRejected("malformed", "a proposal must be an object")
    name = proposal.get("tool")
    if name in FORBIDDEN_INTENTS:
        raise ProposalRejected("forbidden intent", FORBIDDEN_INTENTS[name])
    tool = BY_NAME.get(name or "")
    if tool is None:
        raise ProposalRejected(
            "unknown tool",
            f"{name!r} is not in the allowlisted catalogue {sorted(BY_NAME)}")

    args = proposal.get("arguments")
    if not isinstance(args, dict):
        raise ProposalRejected("malformed", f"{name}: arguments must be an object")
    missing = [f for f in tool.fields if f not in args]
    if missing:
        raise ProposalRejected("incomplete", f"{name}: missing {missing}")
    extra = [k for k in args if k not in tool.fields]
    if extra:
        raise ProposalRejected("unexpected fields", f"{name}: {extra} are not part of this tool")

    key = args.get("taxonomy_key")
    if key is not None and not tax.is_category(key):
        raise ProposalRejected(
            "unknown taxonomy category",
            f"{key!r} is not a category; the agent may only use the curated taxonomy")

    citations = [str(c) for c in (proposal.get("citations") or [])]
    fid = args.get("finding_id")
    if fid:
        citations.append(str(fid))
    citations = sorted(set(citations))
    if tool.requires_citations and not citations:
        raise ProposalRejected("uncited", f"{name} must cite the finding(s) it describes")
    unknown = [c for c in citations if c not in known_finding_ids]
    if unknown:
        raise ProposalRejected(
            "citation not found",
            f"{name} cites {unknown}, which are not findings on this asset")

    return {"tool": tool.name, "arguments": args, "citations": citations,
            "on_accept": tool.on_accept}


def catalogue_for_prompt() -> list[dict]:
    """What the model is told it may return. Data, not instructions to obey."""
    return [{"tool": t.name, "summary": t.summary, "fields": list(t.fields),
             "requires_citations": t.requires_citations} for t in TOOLS]
