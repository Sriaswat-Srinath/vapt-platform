#!/usr/bin/env python3
"""Evaluate the detection engine against the evaluation dataset.

Runs against the live API: it reads the asset's current findings and compares
each case's expected verdict with the verdict the engine actually reached.

  TP  the engine confirmed something the dataset says IS a vulnerability
  TN  the engine refused something the dataset says is NOT one
  FP  the engine confirmed something the dataset says is not a vulnerability
  FN  the engine failed to confirm something the dataset says is one
  --  the engine reached a different non-confirming state than expected

IMPORTANT: this measures the pipeline against CONSTRUCTED evidence whose ground
truth is known by construction. It does not establish real-world detection
accuracy, and the report says so in its own words.

Usage: scripts/detection_eval.py [--asset MOCK-WEB-001] [--json OUT] [--md OUT]
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import pathlib
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8000/api/v1"
DATASET = REPO / "backend" / "fixtures" / "evaluation" / "detection_cases.json"

CONFIRMING = {"confirmed"}
REFUSING = {"false_positive", "not_applicable"}


def api(path: str, token: str):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:          # noqa: S310 - loopback forwarder
        return json.loads(r.read().decode())


def classify(expected: str, actual: str | None, ground_truth: str) -> str:
    if actual is None:
        return "MISSING"
    if actual == expected:
        if ground_truth == "vulnerable":
            return "TP"
        if ground_truth == "not_vulnerable":
            return "TN"
        return "OK"
    if ground_truth == "vulnerable" and actual in REFUSING:
        return "FN"
    if ground_truth == "not_vulnerable" and actual in CONFIRMING:
        return "FP"
    return "MISMATCH"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asset", default="MOCK-WEB-001")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--md", dest="md_out")
    args = ap.parse_args()

    tokens = json.loads((REPO / ".lab-state" / "tokens.json").read_text())
    token = tokens["analyst"]
    assets = api("/assets", token)
    asset = next((a for a in assets if a["asset_identifier"] == args.asset), None)
    if asset is None:
        print(f"asset {args.asset} is not registered", file=sys.stderr)
        return 2
    findings = api(f"/findings?asset_id={asset['id']}&limit=200", token)
    dataset = json.loads(DATASET.read_text())

    # A case matches the finding(s) carrying its catalogue key. An unmapped case
    # matches any finding with no catalogue key.
    by_key: dict[str | None, list[dict]] = {}
    for f in findings:
        by_key.setdefault(f["catalogue_key"], []).append(f)

    results = []
    for case in dataset["cases"]:
        matches = by_key.get(case["catalogue_key"], [])
        states = sorted({m["validation_state"] for m in matches})
        actual = case["expected_state"] if case["expected_state"] in states else (
            states[0] if states else None)
        verdict = classify(case["expected_state"], actual, case["ground_truth"])
        results.append({**case, "observed_states": states, "actual_state": actual,
                        "verdict": verdict, "matched_findings": len(matches)})

    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    summary = {
        "dataset_version": dataset["dataset_version"],
        "evaluated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "asset": args.asset,
        "cases": len(results),
        "counts": counts,
        "false_positives": counts.get("FP", 0),
        "false_negatives": counts.get("FN", 0),
        "unmatched": counts.get("MISSING", 0),
        "caveat": ("Constructed evidence with ground truth known by construction. This measures "
                   "the pipeline's self-consistency, NOT real-world detection accuracy."),
    }
    out = {"summary": summary, "results": results}

    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(out, indent=2))
    if args.md_out:
        lines = [
            "# Detection evaluation", "",
            f"Dataset {dataset['dataset_version']} · {len(results)} cases · "
            f"asset {args.asset} · {summary['evaluated_at']}", "",
            "> **What this measures.** Whether the pipeline reaches the correct verdict for "
            "constructed evidence whose ground truth is known by construction. It does **not** "
            "establish real-world detection accuracy: every case is a hand-authored alert over a "
            "hand-authored response. A perfect score means the engine is self-consistent.", "",
            "| Verdict | Count |", "|---|---|",
        ]
        for k in sorted(counts):
            lines.append(f"| {k} | {counts[k]} |")
        lines += ["", "| Case | Category | Scenario | Ground truth | Expected | Actual | Verdict |",
                  "|---|---|---|---|---|---|---|"]
        for r in results:
            lines.append(
                f"| {r['id']} | {r['category']} | {r['scenario']} | {r['ground_truth']} | "
                f"{r['expected_state']} | {r['actual_state'] or '—'} | **{r['verdict']}** |")
        lines += ["", "## Reading the verdicts", "",
                  "* **TP/TN** — the engine agreed with the dataset.",
                  "* **FP** — the engine confirmed something that is not a vulnerability.",
                  "* **FN** — the engine failed to confirm something that is.",
                  "* **OK** — a non-binary case (candidate, not applicable) matched.",
                  "* **MISSING** — no finding carried that catalogue key: the detection did not "
                  "reach the pipeline at all.", ""]
        pathlib.Path(args.md_out).write_text("\n".join(lines))

    print(json.dumps(summary, indent=2))
    for r in results:
        if r["verdict"] not in ("TP", "TN", "OK"):
            print(f"  {r['verdict']:8} {r['id']} {r['category']:26} "
                  f"expected={r['expected_state']} actual={r['actual_state']}")
    return 0 if not (counts.get("FP") or counts.get("FN") or counts.get("MISSING")) else 1


if __name__ == "__main__":
    sys.exit(main())
