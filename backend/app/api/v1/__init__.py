from fastapi import APIRouter
from . import (agent_api, assets, audit_api, discovery, findings, jobs, reports, scope,
               system, taxonomy_api)

router = APIRouter()
router.include_router(system.router, tags=["system"])
router.include_router(assets.router, tags=["assets"])
router.include_router(scope.router, tags=["scope"])
router.include_router(discovery.router, tags=["discovery"])
router.include_router(jobs.router, tags=["assessments"])
router.include_router(findings.router, tags=["findings"])
router.include_router(taxonomy_api.router, tags=["taxonomy"])
router.include_router(agent_api.router, tags=["agent"])
router.include_router(reports.router, tags=["reports"])
router.include_router(audit_api.router, tags=["audit"])
