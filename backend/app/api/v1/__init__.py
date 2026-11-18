from fastapi import APIRouter
from . import assets, audit_api, discovery, findings, jobs, scope, system

router = APIRouter()
router.include_router(system.router, tags=["system"])
router.include_router(assets.router, tags=["assets"])
router.include_router(scope.router, tags=["scope"])
router.include_router(discovery.router, tags=["discovery"])
router.include_router(jobs.router, tags=["assessments"])
router.include_router(findings.router, tags=["findings"])
router.include_router(audit_api.router, tags=["audit"])
