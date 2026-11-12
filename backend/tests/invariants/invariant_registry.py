"""Registry of the MVP security invariants (docs/INVARIANTS.md).

The manifest test (test_manifest.py) enforces that every invariant exists and
that none stays skipped past its milestone. Adding an invariant is cheap;
removing one requires an ADR.
"""
from __future__ import annotations
import json, pathlib

HERE = pathlib.Path(__file__).parent
REPO = HERE.parents[2]

# id -> (statement, milestone, test module relative to this package or None)
# Milestones follow ROADMAP v2 (2026-11-12): M2 backend+gates, M3 ZAP, M4 discovery,
# M5 validation+evidence, M6 agent, M7 dashboard+reports, M8 hardening.
INVARIANTS: dict[str, tuple[str, str, str | None]] = {
    "I1":  ("No unregistered asset can be scanned",                      "M2",  None),
    "I2":  ("No scan starts without a valid ScopeDecision",              "M2",  None),
    "I3":  ("No active scan runs without genuine dual control",          "M2",  None),
    "I4":  ("No scanner worker has internet access",                     "M1",  "test_i4_no_scanner_egress.py"),
    "I5":  ("No LLM request contains unredacted evidence",               "M6",  None),
    "I6":  ("No finding becomes confirmed solely through LLM output",    "M5",  None),
    "I7":  ("No referenced evidence blob is purged",                     "M5",  None),
    "I8":  ("No new ZAP job starts while daemon state is dirty",         "M3",  None),
    "I9":  ("No unsigned authorisation document activates a scope grant","M2",  None),
    "I10": ("No report represents synthetic findings as real ones",      "M7", None),
    "I11": ("No plain hash of a secret value crosses the LLM boundary",  "M6",  None),
    "I12": ("Purge is idempotent and halts on inconsistency",            "M5",  None),
    "I13": ("Cancellation completes within the SLA",                     "M3",  None),
    "I14": ("Asset identity is immutable",                               "M2",  None),
}

def landed_milestones() -> list[str]:
    return json.loads((HERE / "MILESTONE_STATE.json").read_text())["landed"]
