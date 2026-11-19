#!/usr/bin/env python3
"""Evaluate whatever model the agent is pointed at.

Four scores, all computed from the platform's OWN validator — no new judgement
is invented here:

  json_valid       the response parsed as JSON at all
  schema_valid     it passed tools.validate(): known tool, exact fields, known
                   taxonomy key, no extra keys
  cited            every claim about a finding cited a handle that was supplied
  grounded         every noun the explanation leans on appears in the evidence
                   or the finding metadata it was given

`grounded` is a CRUDE lexical check and is labelled as such: it catches a model
inventing a parameter, path or header that was never in the payload, which is
the hallucination that matters most in a security report. It does not judge
whether the explanation is good. A low grounded score is a reason to read the
output; a high one is not proof of quality.

Run it against any model by pointing LLM_MODEL/LLM_BASE_URL at it and setting
LLM_ENABLED=true. The comparison is only meaningful across identical payloads,
which is why the prompts come from the live platform rather than from a file.

Usage: scripts/agent_eval.py [--runs N] [--md OUT] [--json OUT]
"""
from __future__ import annotations
import argparse
import json
import pathlib
import re
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8000/api/v1"
# A "distinctive" token: something that looks like a path, header, parameter or
# identifier rather than ordinary prose. Trailing sentence punctuation is
# stripped first, or "application." reads as a dotted identifier.
WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{3,}")
# Words any answer may use without them appearing in the payload: the domain's
# own vocabulary, which is not evidence of hallucination.
VOCABULARY = {
    "header", "headers", "response", "request", "application", "server", "client",
    "browser", "security", "finding", "evidence", "scanner", "platform", "stored",
    "vulnerability", "vulnerabilities", "attacker", "policy", "value", "values",
    "content", "missing", "present", "absent", "configure", "configured", "setting",
    "should", "would", "could", "because", "which", "there", "these", "their",
    "this", "that", "with", "from", "into", "when", "where", "what", "does",
    "exploitable", "context", "confirm", "confirmed", "candidate", "remediation",
    "assessment", "synthetic", "target", "shows", "show", "does not", "cannot",
    "taxonomy", "category", "categories", "analyst", "human", "review", "intrusive",
    "passive", "active", "coverage", "rule", "rules", "state", "severity",
}
VOCABULARY |= set()          # extended at runtime with the platform's own keys


def _platform_vocabulary() -> set[str]:
    """The platform's OWN vocabulary, which every relevant prompt supplies:
    taxonomy keys, validation states, catalogue keys. A model using one of
    these is quoting us, not inventing."""
    sys.path.insert(0, str(REPO / "backend"))
    try:
        from app import taxonomy as tax
        from app.catalogue import CATALOGUE
        words = {c.key for c in tax.ALL} | {c.display_name.lower() for c in tax.ALL}
        words |= {c["key"] for c in CATALOGUE}
        return words
    except Exception:                                        # noqa: BLE001
        return set()


def api(path: str, token: str, method: str = "GET"):
    req = urllib.request.Request(BASE + path, method=method,
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=180) as r:     # noqa: S310 - loopback forwarder
        return json.loads(r.read().decode())


def grounded(text: str, payload_text: str, vocabulary: set[str]) -> tuple[bool, list[str]]:
    """Every distinctive word in the answer should be traceable to the payload."""
    haystack = payload_text.lower()
    invented = []
    for raw in {w.lower() for w in WORD.findall(text)}:
        word = raw.rstrip(".,;:)")            # sentence punctuation, not a dotted name
        if not word or word in vocabulary or len(word) < 5:
            continue
        if word in haystack:
            continue
        # Ordinary English that happens to be long is not a hallucination. Only
        # tokens shaped like identifiers — containing a digit, hyphen,
        # underscore, slash or an INTERNAL dot — are held to the evidence.
        # A hyphenated pair of ordinary English words ("re-assess") is prose,
        # not an identifier.
        plain_hyphenated = ("-" in word and word.replace("-", "").isalpha()
                            and all(len(part) > 1 for part in word.split("-")))
        looks_like_identifier = (any(ch.isdigit() for ch in word)
                                 or "_" in word or "/" in word or "." in word
                                 or ("-" in word and not plain_hyphenated))
        if not looks_like_identifier:
            continue
        # A taxonomy key is the platform's own vocabulary, supplied in the prompt.
        if word.replace("_", "") in haystack.replace("_", ""):
            continue
        invented.append(word)
    return (not invented), sorted(invented)[:8]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--md", dest="md_out")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    token = json.loads((REPO / ".lab-state" / "tokens.json").read_text())["analyst"]
    caps = api("/agent/capabilities", token)
    if not caps["llm_enabled"]:
        print("LLM_ENABLED is false — nothing to evaluate. Point the agent at a model first.",
              file=sys.stderr)
        return 2
    assets = api("/assets", token)
    asset = next(a for a in assets if a["asset_identifier"] == "MOCK-WEB-001")

    vocabulary = VOCABULARY | _platform_vocabulary()
    runs = []
    for _ in range(args.runs):
        runs.append(api(f"/assets/{asset['id']}/agent/runs", token, method="POST"))

    questions = accepted = rejected = 0
    wrong_tool = uncited = malformed = schema_bad = 0
    ungrounded: list[dict] = []
    tokens_in = tokens_out = 0

    for run in runs:
        if run["state"] != "completed":
            print(f"run {run['id'][:8]} ended {run['state']}: {run['error']}", file=sys.stderr)
            continue
        tokens_in += run["bytes_sent"] or 0
        tokens_out += run["bytes_received"] or 0
        questions += (run["boundary_report"] or {}).get("questions", 0)
        accepted += len(run["proposals"])
        for r in run["rejected"]:
            rejected += 1
            reason = r.get("reason", "")
            if reason == "unparseable":
                malformed += 1
            elif reason == "wrong tool":
                wrong_tool += 1
            elif reason in ("uncited", "citation not found"):
                uncited += 1
            elif reason != "forbidden intent":
                schema_bad += 1
        for p in run["proposals"]:
            text = " ".join(str(v) for k, v in p["arguments"].items() if k != "finding_id")
            # The haystack is the EVIDENCE ONLY. Including the proposal's own
            # text would make every word trivially "grounded" — the needle
            # cannot be part of the haystack.
            payload_text = ""
            for fid in p["citations"]:
                try:
                    detail = api(f"/findings/{fid}", token)
                    payload_text += json.dumps({
                        k: detail.get(k) for k in
                        ("title", "category", "affected_url", "parameter_name",
                         "catalogue_key", "severity", "validation_state",
                         "description_md", "remediation_md")})
                    for ev in detail.get("evidence", []):
                        try:
                            payload_text += json.dumps(
                                api(f"/evidence/{ev['id']}/content", token).get("content") or "")
                        except Exception:                    # noqa: BLE001
                            pass
                except Exception:                            # noqa: BLE001
                    pass
            ok, invented = grounded(text, payload_text, vocabulary)
            if not ok:
                ungrounded.append({"tool": p["tool"], "invented": invented,
                                   "excerpt": text[:160]})

    summary = {
        "model": caps["model"], "provider": caps["provider_host"],
        "runs": len(runs), "questions_asked": questions,
        "proposals_accepted": accepted,
        "rejected_total": rejected,
        "malformed_json": malformed,
        "schema_violations": schema_bad,
        "wrong_tool": wrong_tool,
        "uncited_or_invented_citation": uncited,
        "ungrounded_proposals": len(ungrounded),
        "tokens_in": tokens_in, "tokens_out": tokens_out,
        "schema_pass_rate": round(accepted / max(1, accepted + schema_bad + malformed), 3),
        "caveat": ("`grounded` is a crude lexical check: it catches invented paths, parameters "
                   "and headers, not poor reasoning. A high score is not proof of quality. "
                   "Scores are comparable only across identical payloads."),
    }
    out = {"summary": summary, "ungrounded": ungrounded}
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(out, indent=2))
    if args.md_out:
        L = [f"# Agent model evaluation — {summary['model']}", "",
             f"Provider `{summary['provider']}` · {summary['runs']} run(s) · "
             f"{summary['questions_asked']} question(s)", "",
             f"> {summary['caveat']}", "",
             "| Metric | Value |", "|---|---|"]
        for k in ("proposals_accepted", "malformed_json", "schema_violations", "wrong_tool",
                  "uncited_or_invented_citation", "ungrounded_proposals", "schema_pass_rate",
                  "tokens_in", "tokens_out"):
            L.append(f"| {k.replace('_', ' ')} | {summary[k]} |")
        if ungrounded:
            L += ["", "## Proposals using words absent from their payload", "",
                  "| Tool | Invented terms | Excerpt |", "|---|---|---|"]
            for u in ungrounded[:20]:
                L.append(f"| `{u['tool']}` | {', '.join(u['invented'])} | {u['excerpt']} |")
        L.append("")
        pathlib.Path(args.md_out).write_text("\n".join(L))

    print(json.dumps(summary, indent=2))
    for u in ungrounded[:10]:
        print(f"  UNGROUNDED {u['tool']}: {u['invented']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
