"""The vulnerability taxonomy and this build's coverage of it."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ... import coverage as cv
from ... import errors, models
from ...config import settings
from ...db import get_session
from ...deps import Principal, require_role
from ... import services

router = APIRouter()


@router.get("/taxonomy")
def taxonomy(session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    """Every category, including the ones this build cannot detect."""
    rows = session.execute(select(models.VulnTaxonomy).order_by(
        models.VulnTaxonomy.sort_index)).scalars().all()
    return [{"key": r.key, "display_name": r.display_name, "tier": r.tier,
             "priority": r.priority, "assertability": r.assertability,
             "owasp_2021": r.owasp_2021, "description": r.description,
             "taxonomy_version": r.taxonomy_version} for r in rows]


def _coverage_rows(session: Session, asset: models.Asset) -> list[cv.CategoryCoverage]:
    candidates = dict(session.execute(
        select(models.CandidateTest.concern, func.count())
        .where(models.CandidateTest.asset_id == asset.id)
        .group_by(models.CandidateTest.concern)).all())
    findings: dict[str, dict[str, int]] = {}
    for category, state, n in session.execute(
            select(models.Finding.category, models.Finding.validation_state, func.count())
            .where(models.Finding.asset_id == asset.id,
                   models.Finding.quarantined_at.is_(None))
            .group_by(models.Finding.category, models.Finding.validation_state)).all():
        findings.setdefault(category, {})[state] = n
    s = settings()
    dual = services.effective_dual_control(session)
    return cv.compute(candidate_counts=candidates, finding_counts=findings,
                      scanner_execution_enabled=s.scanner_execution_enabled,
                      active_scan_enabled=s.active_scan_enabled,
                      dual_control_effective=bool(dual))


@router.get("/assets/{asset_id}/coverage")
def coverage(asset_id: str, session: Session = Depends(get_session),
             p: Principal = Depends(require_role("analyst", "approver", "admin"))):
    """Per-category coverage for this asset — the zeroes included.

    Separates three different things a reader otherwise conflates: what the
    OWNER prioritised (tier, priority), what THIS BUILD can assert (detection),
    and what was actually found (findings).
    """
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    rows = _coverage_rows(session, asset)
    # A detection whose category the taxonomy does not define must be visible,
    # not silently absent from every total.
    unmapped = session.execute(
        select(func.count()).select_from(models.Finding).where(
            models.Finding.asset_id == asset.id,
            models.Finding.category.not_in([r.key for r in rows]))).scalar_one()
    return {"asset_id": str(asset.id), "asset_identifier": asset.asset_identifier,
            "summary": {**cv.summary(rows), "uncategorised_findings": unmapped},
            "categories": [r.as_dict() for r in rows]}
