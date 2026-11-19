#!/usr/bin/env python3
"""Compare a completed assessment against the M9 ground-truth expectations.

Step 10 of the M9 sequence. Three questions, kept apart because they mean
different things:

  matched     expected and found       — the pipeline saw what it should
  missed      expected and NOT found   — a recall gap, OR the crawl never got
                                         there, OR the deployment differs
  unexpected  found and not expected   — may be real, may be a false positive;
                                         either way it needs an analyst's eye

A missed expectation is deliberately NOT called a failure: this script asks the
question, it does not answer it. Confidence is carried through from the dataset
so a missed `low` expectation reads differently from a missed `high` one.

Usage: scripts/m9_compare.py [--job JOB_ID] [--md OUT] [--json OUT]
"""
from __future__ import annotations
import argparse
import json
import pathlib
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8000/api/v1"
GT = REPO / "backend" / "fixtures" / "evaluation" / "m9_ground_truth.json"


def api(path: str, token: str):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:          # noqa: S310 - loopback forwarder
        return json.loads(r.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job")
    ap.add_argument("--md", dest="md_out")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    token = json.loads((REPO / ".lab-state" / "tokens.json").read_text())["analyst"]
    gt = json.loads(GT.read_text())
    assets = api("/assets", token)
    asset = next(a for a in assets if a["asset_identifier"] == gt["target"]["asset_identifier"])
    findings = api(f"/findings?asset_id={asset['id']}&limit=300", token)

    job_mode = None
    if args.job:
        job = api(f"/assessments/{args.job}", token)
        job_mode = job["mode"]
        findings = [f for f in findings if f.get("job_id") == args.job] or findings

    by_key: dict[str | None, list[dict]] = {}
    for f in findings:
        by_key.setdefault(f["catalogue_key"], []).append(f)

    matched, missed = [], []
    for e in gt["expectations"]:
        if e.get("surface_only"):
            continue
        found = by_key.get(e["catalogue_key"], [])
        row = {**e, "found": len(found),
               "states": sorted({f["validation_state"] for f in found})}
        (matched if found else missed).append(row)

    expected_keys = {e["catalogue_key"] for e in gt["expectations"]}
    unexpected = [
        {"catalogue_key": k or "(unmapped)", "count": len(v),
         "titles": sorted({f["title"] for f in v})[:3],
         "states": sorted({f["validation_state"] for f in v})}
        for k, v in by_key.items() if k not in expected_keys]

    summary = {
        "dataset_version": gt["dataset_version"],
        "mode": job_mode or "(all assessments for this asset)",
        "expectations": len([e for e in gt["expectations"] if not e.get("surface_only")]),
        "matched": len(matched), "missed": len(missed), "unexpected": len(unexpected),
        "missed_high_confidence": len([m for m in missed if m["confidence"] == "high"]),
        "caveat": ("A missed expectation is a QUESTION, not a verdict: the crawl may not have "
                   "reached the page, the budget may have been exhausted, or the deployment may "
                   "differ from the published default."),
    }
    if job_mode == "fixture":
        summary["warning"] = ("This compares FIXTURE output against real-world expectations. It "
                              "says nothing about live detection. Re-run against a live job.")

    out = {"summary": summary, "matched": matched, "missed": missed, "unexpected": unexpected}
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(out, indent=2))
    if args.md_out:
        L = ["# M9 — findings vs independently known weaknesses", "",
             f"Dataset {gt['dataset_version']} · mode **{summary['mode']}** · "
             f"{summary['matched']}/{summary['expectations']} expectations matched", ""]
        if "warning" in summary:
            L += [f"> **{summary['warning']}**", ""]
        L += [f"> {summary['caveat']}", "",
              "## Expected and found", "",
              "| ID | Category | Expectation | Confidence | Findings | States |", "|---|---|---|---|---|---|"]
        for m in matched:
            L.append(f"| {m['id']} | {m['category']} | {m['expectation']} | {m['confidence']} | "
                     f"{m['found']} | {', '.join(m['states'])} |")
        L += ["", "## Expected and NOT found", ""]
        if missed:
            L += ["| ID | Category | Expectation | Confidence | Basis |", "|---|---|---|---|---|"]
            for m in missed:
                L.append(f"| {m['id']} | {m['category']} | {m['expectation']} | "
                         f"{m['confidence']} | {m['basis']} |")
        else:
            L.append("None.")
        L += ["", "## Found but not expected", ""]
        if unexpected:
            L += ["| Catalogue key | Count | States | Examples |", "|---|---|---|---|"]
            for u in unexpected:
                L.append(f"| `{u['catalogue_key']}` | {u['count']} | {', '.join(u['states'])} | "
                         f"{'; '.join(u['titles'])} |")
        else:
            L.append("None.")
        L += ["", "## Out of passive reach by construction", ""]
        L += [f"* {x}" for x in gt["not_expected_passively"]]
        L.append("")
        pathlib.Path(args.md_out).write_text("\n".join(L))

    print(json.dumps(summary, indent=2))
    for m in missed:
        print(f"  MISSED     {m['id']} ({m['confidence']}) {m['expectation']}")
    for u in unexpected:
        print(f"  UNEXPECTED {u['catalogue_key']} x{u['count']} {u['states']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
