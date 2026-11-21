"""The bounded agent run: one focused request per question, each validated.

Deliberately bounded rather than a free-running loop. The agent has no tools it
can execute, so iteration buys nothing a second analyst request would not.

Version 2 asks SEVERAL SMALL questions instead of one enormous one. Each tool
gets its own request carrying only what that question needs — a finding and its
evidence, or a coverage row — typically 400-1,200 tokens instead of ~6,900. A
model asked one question answers it better than a model asked six at once, and
a smaller payload is less to leak as well as less to pay for.

What the model is never given: unredacted evidence, platform tokens, the
provider API key, connection strings, internal addresses, or any instruction
from the scanned application that has not been through the stage-2 boundary.

Model output is DATA. It is parsed, validated against a fixed catalogue and
stored; it is never executed, and it never reaches the validation engine, the
gate chain or a scanner. A rejected proposal is RECORDED, because a model
trying to do something it cannot is the behaviour most worth seeing.
"""
from __future__ import annotations
import datetime as dt
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from .. import taxonomy as tax
from ..api.v1.taxonomy_api import _coverage_rows
from ..catalogue import CATALOGUE
from ..config import settings
from . import client, prompts, tools
from .boundary import BoundaryRefusal, enforce
from .parsing import parse_proposals

RUNNER_VERSION = "2.0.0"
PROMPT_VERSION = prompts.PROMPT_VERSION

CATALOGUE_REMEDIATION = {c["key"]: c["remediation_md"] for c in CATALOGUE}


def _finding_row(f: models.Finding) -> dict[str, Any]:
    return {"id": str(f.id), "title": f.title, "category": f.category,
            "validation_state": f.validation_state,
            "validation_rule_id": f.validation_rule_id, "severity": f.severity,
            "coverage_complete": bool(f.coverage_complete),
            "affected_url": f.affected_url, "parameter_name": f.parameter_name,
            "catalogue_key": f.catalogue_key, "unmapped_rule_id": f.unmapped_rule_id}


def _evidence(session: Session, finding_id: Any) -> list[str]:
    rows = session.execute(select(models.Evidence).where(
        models.Evidence.finding_id == finding_id)).scalars().all()
    return [e.content_redacted for e in rows if e.content_redacted]


def build_prompts(session: Session, asset: models.Asset, *,
                  limit: int | None = None) -> list[prompts.Prompt]:
    """The questions worth asking about THIS asset, in priority order.

    Chosen deterministically: the agent does not decide what to look at, it
    answers what the platform decided is worth asking. Handles (`f1`, `f2`, …)
    are scoped to a single prompt, so a model cannot cite a finding it was not
    given in that request.
    """
    s = settings()
    limit = limit or s.llm_max_findings
    out: list[prompts.Prompt] = []

    findings = session.execute(
        select(models.Finding)
        .where(models.Finding.asset_id == asset.id,
               models.Finding.quarantined_at.is_(None))
        .order_by(models.Finding.last_seen_at.desc()).limit(limit)).scalars().all()

    # 1. Unmapped detections first: a category the platform could not assign is
    #    the one place an advisory opinion has somewhere concrete to go.
    for n, f in enumerate((x for x in findings if x.catalogue_key is None), start=1):
        out.append(prompts.map_unmapped_detection(
            f"f{n}", _finding_row(f), _evidence(session, f.id)))

    # 2. Explanations and remediation for what a report will actually carry.
    reportable = [f for f in findings if f.validation_state in ("confirmed", "candidate")]
    for n, f in enumerate(reportable[:s.llm_max_explanations], start=1):
        row = _finding_row(f)
        evidence = _evidence(session, f.id)
        out.append(prompts.explain_finding(f"f{n}", row, evidence))
        out.append(prompts.suggest_remediation(
            f"f{n}", row, evidence, CATALOGUE_REMEDIATION.get(f.catalogue_key or "")))

    # 3. One coverage gap, chosen by priority rather than by the model.
    gaps = [r for r in _coverage_rows(session, asset)
            if r.tier == 1 and r.detection in ("none", "catalogued")]
    if gaps:
        # CategoryCoverage carries no sort index; the taxonomy's own order is
        # the owner's priority order, so use that.
        order = {c.key: c.sort_index for c in tax.ALL}
        worst = sorted(gaps, key=lambda r: (r.priority != "critical", order.get(r.key, 99)))[0]
        out.append(prompts.summarise_coverage_gap(
            {"category": worst.key, "name": worst.display_name, "priority": worst.priority,
             "detection": worst.detection, "candidates": worst.candidates,
             "blocked_by": list(worst.blocked_by)}))

    # 4. Candidate-test ranking, if there is anything to rank.
    candidates = session.execute(select(models.CandidateTest).where(
        models.CandidateTest.asset_id == asset.id).limit(40)).scalars().all()
    if candidates:
        out.append(prompts.prioritise_candidate_tests(
            [{"concern": c.concern, "surface_kind": c.surface_kind,
              "requires_intrusive": bool(c.requires_intrusive)} for c in candidates]))
    return out


def _stop(session: Session, run_row: models.AgentRun, rejected: list[dict[str, Any]],
          boundary_fields: int, questions: int) -> models.AgentRun:
    """End a run early, still recording what the boundary checked.

    A disabled or failed run has usually already built and ENFORCED a payload;
    recording that proves the outbound check ran even though nothing was sent.
    """
    run_row.rejected = rejected or None
    run_row.boundary_report = {"checked_fields": boundary_fields, "questions": questions,
                               "re_redacted_fields": 0}
    run_row.finished_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    return run_row


def run(session: Session, asset: models.Asset, *, actor_id: str | None) -> models.AgentRun:
    """One bounded pass: several focused requests, every answer validated.

    The run is recorded whatever happens — including `disabled` and `refused` —
    because a run that never left the building is exactly the one worth being
    able to prove afterwards.
    """
    s = settings()
    questions = build_prompts(session, asset)
    # The same cost control the conversational path has: an agent run that
    # talks to a paid API needs a ceiling, and "it got expensive" should be a
    # recorded refusal rather than a surprise on an invoice.
    budget = s.llm_run_token_budget

    run_row = models.AgentRun(
        asset_id=asset.id, state="running", runner_version=RUNNER_VERSION,
        prompt_version=PROMPT_VERSION, tool_catalogue_version=tools.TOOL_CATALOGUE_VERSION,
        boundary_version=None, model=s.llm_model, provider_host=None,
        requested_by=actor_id, started_at=dt.datetime.now(dt.timezone.utc))
    session.add(run_row)
    session.flush()

    rejected: list[dict[str, Any]] = []
    accepted_total = 0
    sent = received = 0
    boundary_fields = 0

    for question in questions:
        if sent + received >= budget:
            rejected.append({"reason": "run budget exhausted", "tool": question.tool,
                             "detail": (f"{sent + received} tokens used of the {budget} "
                                        "per-run budget; the remaining questions were not "
                                        "asked")})
            break
        payload = prompts.as_request(question)
        try:
            checked, report = enforce(payload)
            run_row.boundary_version = report.boundary_version
            boundary_fields += report.checked_fields
        except BoundaryRefusal as exc:
            # One refused question does not abandon the run, but it IS recorded:
            # a payload that should never have been built is a defect upstream.
            rejected.append({"reason": f"boundary: {exc.rule}", "detail": exc.detail,
                             "tool": question.tool})
            continue

        try:
            response = client.send(question.system, checked)
        except client.LlmDisabled as exc:
            run_row.state = "disabled"
            run_row.error = (f"{exc}. The agent is advisory and off by default; enabling it "
                             "changes nothing about what the platform will execute.")
            return _stop(session, run_row, rejected, boundary_fields, len(questions))
        except (client.LlmRefused, BoundaryRefusal) as exc:
            run_row.state = "failed"
            run_row.error = str(exc)
            return _stop(session, run_row, rejected, boundary_fields, len(questions))

        sent += response.input_tokens
        received += response.output_tokens
        run_row.provider_host = response.provider_host
        run_row.model = response.model

        accepted, bad = parse_proposals(response.text, known_finding_ids=set(question.handles))
        for item in bad:
            rejected.append({**item, "asked_for": question.tool})

        for p in accepted:
            if p["tool"] != question.tool:
                # Answering a different question than the one asked is not a
                # proposal, it is drift. Recorded, not stored.
                rejected.append({"reason": "wrong tool", "tool": p["tool"],
                                 "detail": f"the request asked for {question.tool}",
                                 "asked_for": question.tool})
                continue
            arguments = dict(p["arguments"])
            if "finding_id" in arguments:
                arguments["finding_id"] = question.handles[str(arguments["finding_id"])]
            session.add(models.AgentProposal(
                run_id=run_row.id, asset_id=asset.id, tool=p["tool"], arguments=arguments,
                citations=[question.handles[c] for c in p["citations"]], state="proposed"))
            accepted_total += 1

    run_row.bytes_sent = sent                     # tokens, not bytes, since v2
    run_row.bytes_received = received
    run_row.elapsed_ms = int(
        (dt.datetime.now(dt.timezone.utc) - run_row.started_at).total_seconds() * 1000)
    run_row.rejected = rejected or None
    run_row.boundary_report = {"checked_fields": boundary_fields,
                               "questions": len(questions),
                               "re_redacted_fields": 0}
    run_row.state = "completed" if questions else "completed"
    run_row.finished_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    return run_row
