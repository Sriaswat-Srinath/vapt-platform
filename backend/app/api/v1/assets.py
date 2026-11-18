"""Asset registration and management. Registering anything that is not a
synthetic lab asset is rejected — by validation, by a DB CHECK, and by the
environment policy (invariants I1, I14)."""
from __future__ import annotations
import ipaddress
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from ... import audit, errors, models, schemas, services
from ...config import settings
from ...db import get_session
from ...deps import Principal, require_role, trace_id

router = APIRouter()


def _reject_non_lab_target(hostname: str) -> None:
    """Deterministic rejection of anything outside the synthetic lab.

    The asset's hostname must be a lab name AND must resolve inside the lab
    subnet. A public hostname, a public IP literal or an unresolvable name is
    refused here, before a row exists.
    """
    lab_net = ipaddress.ip_network(settings().lab_subnet)
    reasons: list[str] = []
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and literal not in lab_net:
        reasons.append(f"{hostname} is an IP literal outside the lab subnet {lab_net}")
    if literal is None and not hostname.endswith(".test"):
        reasons.append(f"{hostname!r} is not a reserved .test lab hostname (RFC 6761)")
    # Resolution is advisory HERE: the API has no route to vapt_lab by design, so
    # a lab name legitimately fails to resolve from this process. If it DOES
    # resolve and lands outside the lab subnet, that is decisive — reject.
    # Authoritative resolve-once-and-pin happens in the worker at gate 8.
    resolved, _err = services.resolve_host(hostname)
    outside = [ip for ip in resolved if ipaddress.ip_address(ip) not in lab_net]
    if outside:
        reasons.append(f"{hostname} resolves to {outside}, outside the lab subnet {lab_net}")
    if reasons:
        raise errors.conflict(
            "target-out-of-scope", "Target is not a registered synthetic lab asset",
            "; ".join(reasons),
            {"lab_subnet": str(lab_net), "hostname": hostname, "reasons": reasons})


@router.get("/assets", response_model=list[schemas.AssetOut])
def list_assets(session: Session = Depends(get_session),
                p: Principal = Depends(require_role("analyst", "approver"))):
    return session.execute(select(models.Asset).order_by(models.Asset.created_at)).scalars().all()


@router.post("/assets", response_model=schemas.AssetOut, status_code=201)
def register_asset(payload: schemas.AssetCreate, session: Session = Depends(get_session),
                   p: Principal = Depends(require_role("analyst")),
                   trace: str = Depends(trace_id)):
    _reject_non_lab_target(payload.hostname)
    asset = models.Asset(**payload.model_dump(), created_by=p.analyst.id, state="active")
    session.add(asset)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise errors.conflict("asset-conflict", "Asset already registered",
                              f"{payload.hostname}:{payload.port} or identifier "
                              f"{payload.asset_identifier!r} is already registered") from exc
    audit.record(session, action="asset_registered", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="asset", subject_id=str(asset.id), trace_id=trace,
                 detail={"asset_identifier": asset.asset_identifier,
                         "hostname": asset.hostname, "port": asset.port})
    session.commit()
    return asset


@router.get("/assets/{asset_id}", response_model=schemas.AssetOut)
def get_asset(asset_id: str, session: Session = Depends(get_session),
              p: Principal = Depends(require_role("analyst", "approver"))):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    return asset


@router.patch("/assets/{asset_id}", response_model=schemas.AssetOut)
def update_asset(asset_id: str, payload: schemas.AssetUpdate,
                 session: Session = Depends(get_session),
                 p: Principal = Depends(require_role("analyst")),
                 trace: str = Depends(trace_id)):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    changes = payload.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(asset, k, v)
    audit.record(session, action="asset_updated", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="asset", subject_id=str(asset.id),
                 trace_id=trace, detail={"changed": sorted(changes)})
    session.commit()
    return asset


@router.post("/assets/{asset_id}/archive", response_model=schemas.AssetOut)
def archive_asset(asset_id: str, session: Session = Depends(get_session),
                  p: Principal = Depends(require_role("analyst")),
                  trace: str = Depends(trace_id)):
    asset = session.get(models.Asset, asset_id)
    if asset is None:
        raise errors.not_found("Asset")
    asset.state = "archived"
    audit.record(session, action="asset_archived", actor_kind="human", actor_id=p.id,
                 outcome="ok", subject_type="asset", subject_id=str(asset.id), trace_id=trace)
    session.commit()
    return asset
