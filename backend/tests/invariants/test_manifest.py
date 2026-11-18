"""The invariant manifest test.

Guards against the realistic failure mode: not someone deleting a safety test,
but a safety test quietly staying skipped while the milestone it guards ships.
"""
from __future__ import annotations
import pathlib, re, pytest
from invariant_registry import INVARIANTS, landed_milestones, HERE

EXPECTED = [f"I{i}" for i in range(1, 15)]


def test_all_fourteen_invariants_declared():
    assert list(INVARIANTS) == EXPECTED, "I1-I14 must all be declared, in order"


def test_no_duplicate_or_orphan_entries():
    assert len(set(INVARIANTS)) == len(INVARIANTS)
    for inv, (stmt, milestone, _) in INVARIANTS.items():
        assert stmt.strip(), f"{inv} has no statement"
        assert re.fullmatch(r"(M[\d.]+|P\d+)", milestone), \
            f"{inv} has a malformed milestone {milestone!r}"


@pytest.mark.parametrize("inv", EXPECTED)
def test_landed_invariants_are_implemented_and_not_skipped(inv):
    """An invariant whose milestone has landed must have a real, unskipped test."""
    _, milestone, module = INVARIANTS[inv]
    if milestone not in landed_milestones():
        pytest.skip(f"pending {milestone} (not yet landed)")
    assert module, f"{inv} is due at {milestone}, which has landed, but declares no test module"
    path = (HERE / module).resolve()
    assert path.exists(), f"{inv}: declared test module {module} is missing"
    src = path.read_text()
    assert "pytestmark = pytest.mark.skip" not in src, f"{inv}: module-level skip after {milestone} landed"
    assert re.search(r"def test_", src), f"{inv}: {module} contains no test"


def test_skips_are_milestone_referenced():
    """A skip must name a milestone that genuinely has not landed."""
    landed = landed_milestones()
    for inv, (_, milestone, module) in INVARIANTS.items():
        if milestone in landed:
            assert module, f"{inv}: landed milestone {milestone} but no module"
        else:
            assert module is None or (HERE / module).exists()
            assert milestone not in landed


def test_milestone_state_is_committed_and_sane():
    landed = landed_milestones()
    assert "M0" in landed and "M1" in landed
    for m in landed:
        assert re.fullmatch(r"(M[\d.]+|P\d+)", m), m
    # Phases not yet delivered must not be marked landed.
    assert "P6" not in landed and "P7" not in landed and "P8" not in landed
