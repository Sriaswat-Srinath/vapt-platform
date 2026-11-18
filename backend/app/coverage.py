"""Coverage of the taxonomy by THIS build, computed from data.

The question a stakeholder actually asks is not "what did you find?" but "what
could you have found?". This module answers the second one, per category,
including the categories where the answer is nothing.

Nothing here is an estimate. Every number is counted from the catalogue, the
rule packs, the discovery matrix and the stored findings.
"""
from __future__ import annotations
import dataclasses as dc

from . import taxonomy as tax
from .catalogue import CATALOGUE
from .discovery import classify
from .validation import engine as ve

# How a category's detection capability is described. Ordered worst-first so a
# report can lead with the gaps.
NONE = "none"                 # no catalogue entry at all: invisible to this build
CATALOGUED = "catalogued"     # an entry exists, but no rule pack can confirm it
SURFACE_ONLY = "surface_only"  # discovery flags the surface; confirmation needs what we lack
PARTIAL = "partial"           # some detections are decidable; the CATEGORY needs more
DETECTS = "detects"           # catalogue entry + a rule pack that can reach a verdict

# Which evidence classes a rule pack can actually decide, and the taxonomy
# categories whose catalogue entries use them. Derived, not declared.
DECIDABLE_CLASSES = tuple(k for k, fn in ve.RULE_PACKS.items()
                          if fn is not ve._rule_unmapped)  # noqa: SLF001


@dc.dataclass(frozen=True, slots=True)
class CategoryCoverage:
    key: str
    display_name: str
    tier: int
    priority: str
    assertability: str
    owasp_2021: str | None
    description: str
    catalogue_entries: int
    decidable_entries: int
    candidates: int
    findings_total: int
    findings_by_state: dict[str, int]
    detection: str
    blocked_by: tuple[str, ...]
    note: str

    def as_dict(self) -> dict:
        d = dc.asdict(self)
        d["blocked_by"] = list(self.blocked_by)
        return d


def _catalogue_index(plugin_map: dict[str, tuple[str, str]]) -> dict[str, set[str]]:
    """catalogue key -> evidence classes a scanner rule maps it to."""
    out: dict[str, set[str]] = {}
    for _plugin, (key, evidence_class) in plugin_map.items():
        if key:
            out.setdefault(key, set()).add(evidence_class)
    return out


def compute(*, candidate_counts: dict[str, int],
            finding_counts: dict[str, dict[str, int]],
            scanner_execution_enabled: bool,
            active_scan_enabled: bool,
            dual_control_effective: bool) -> list[CategoryCoverage]:
    """One row per taxonomy category, zeroes included.

    `candidate_counts`  concern -> number of flagged surfaces
    `finding_counts`    category -> {validation_state: count}
    """
    from .normalization.zap_mapping import PLUGIN_MAP
    mapped = _catalogue_index(PLUGIN_MAP)

    rows: list[CategoryCoverage] = []
    for cat in tax.ALL:
        entries = [c for c in CATALOGUE if c["category"] == cat.key]
        decidable = [c for c in entries
                     if mapped.get(c["key"], set()) & set(DECIDABLE_CLASSES)]
        states = dict(finding_counts.get(cat.key, {}))
        total = sum(states.values())
        candidates = candidate_counts.get(cat.key, 0)

        blocked: list[str] = []
        if cat.assertability == tax.ACTIVE:
            if not active_scan_enabled:
                blocked.append("active scanning is disabled")
            if not dual_control_effective:
                blocked.append("intrusive testing needs two independent approvals")
        if cat.assertability == tax.MANUAL:
            blocked.append("no automated rule can confirm this category")
        if not scanner_execution_enabled:
            blocked.append("scanner execution is disabled")

        if not entries:
            detection = NONE
            note = ("No catalogue entry exists for this category, so this build cannot report "
                    "it at all. Its absence from a report says nothing about the target.")
        elif decidable and cat.assertability == tax.PASSIVE:
            detection = DETECTS
            note = (f"{len(decidable)} catalogue entr(ies) are reachable by a deterministic rule "
                    "pack over stored evidence.")
        elif decidable:
            detection = PARTIAL
            need = ("crafted requests" if cat.assertability == tax.ACTIVE
                    else "human judgement")
            note = (f"{len(decidable)} catalogue entr(ies) can be validated from stored evidence, "
                    f"but the category as a whole needs {need}. Treat a clean result here as "
                    "partial, not as a clean bill of health.")
        elif candidates:
            detection = SURFACE_ONLY
            note = ("Discovery flags the surface, but confirming it needs evidence this build "
                    "does not collect. Findings here stay candidates.")
        else:
            detection = CATALOGUED
            note = ("A catalogue entry exists so a detection can be mapped and scored, but "
                    "nothing in this build produces or confirms one.")

        rows.append(CategoryCoverage(
            key=cat.key, display_name=cat.display_name, tier=cat.tier, priority=cat.priority,
            assertability=cat.assertability, owasp_2021=cat.owasp_2021,
            description=cat.description, catalogue_entries=len(entries),
            decidable_entries=len(decidable), candidates=candidates,
            findings_total=total, findings_by_state=states, detection=detection,
            blocked_by=tuple(blocked), note=note))
    return rows


def summary(rows: list[CategoryCoverage]) -> dict:
    t1 = [r for r in rows if r.tier == 1]
    detects = [r for r in t1 if r.detection == DETECTS]
    silent = [r for r in t1 if r.detection == NONE]
    return {
        "taxonomy_version": tax.TAXONOMY_VERSION,
        "matrix_version": classify.MATRIX_VERSION,
        "rules_version": ve.RULES_VERSION,
        "tier1_total": len(t1),
        "tier1_detecting": len(detects),
        "tier1_surface_only": len([r for r in t1 if r.detection == SURFACE_ONLY]),
        "tier1_partial": len([r for r in t1 if r.detection == PARTIAL]),
        "tier1_catalogued_only": len([r for r in t1 if r.detection == CATALOGUED]),
        "tier1_no_capability": len(silent),
        "tier1_with_findings": len([r for r in t1 if r.findings_total > 0]),
        "categories_this_build_cannot_report": [r.key for r in silent],
        "note": ("`detects` means a deterministic rule pack can reach a verdict from stored "
                 "evidence. Every other state means the absence of findings in that category "
                 "is not evidence of their absence in the target."),
    }
