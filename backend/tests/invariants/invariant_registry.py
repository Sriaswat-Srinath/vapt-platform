"""Registry of the MVP security invariants (docs/INVARIANTS.md).

The manifest test (test_manifest.py) enforces that every invariant exists and
that none stays skipped past its milestone. Adding an invariant is cheap;
removing one requires an ADR.
"""
from __future__ import annotations
import json, pathlib

HERE = pathlib.Path(__file__).parent
REPO = HERE.parents[2]

# id -> (statement, milestone, test module or an external test path)
#
# Milestones use the MVP phase numbering actually being delivered (docs/MVP_PLAN.md):
#   M1 lab · M1.5 network · P1 datastores · P2 backend+gates · P3 discovery ·
#   P4 scanner adapters · P5 findings+validation · P6 agent · P7 dashboard+reports ·
#   P8 hardening. MILESTONE_STATE.json records which have been delivered.
INVARIANTS: dict[str, tuple[str, str, str | None]] = {
    "I1":  ("No unregistered asset can be scanned",                      "P2",  "../../../tests/backend/test_backend_core.py"),
    "I2":  ("No scan starts without a valid ScopeDecision",              "P2",  "../../../tests/backend/test_backend_core.py"),
    "I3":  ("No active scan runs without genuine dual control",          "P2",  "../../../tests/backend/test_backend_core.py"),
    "I4":  ("No scanner worker has internet access",                     "M1",  "test_i4_no_scanner_egress.py"),
    "I5":  ("No LLM request contains unredacted evidence",               "P6",  "../../../tests/backend/test_agent_phase6.py"),
    "I6":  ("No finding becomes confirmed solely through LLM output",    "P5",  "../../../tests/backend/test_findings_phase5.py"),
    "I7":  ("No referenced evidence blob is purged",                     "P5",  "../../../tests/backend/test_findings_phase5.py"),
    "I8":  ("No new ZAP job starts while daemon state is dirty",         "P4",  "../../../tests/backend/test_scanner_phase4.py"),
    "I9":  ("No unsigned authorisation document activates a scope grant","P2",  "../../../tests/backend/test_backend_core.py"),
    "I10": ("No report represents synthetic findings as real ones",      "P7",  "../../../tests/backend/test_reports_phase7.py"),
    "I11": ("No plain hash of a secret value crosses the LLM boundary",  "P6",  "../../../tests/backend/test_agent_phase6.py"),
    "I12": ("Purge is idempotent and halts on inconsistency",            "P8",  None),
    "I13": ("Cancellation completes within the SLA",                     "P4",  "../../../tests/backend/test_scanner_phase4.py"),
    "I14": ("Asset identity is immutable",                               "P2",  "../../../tests/backend/test_backend_core.py"),
}

def landed_milestones() -> list[str]:
    return json.loads((HERE / "MILESTONE_STATE.json").read_text())["landed"]
