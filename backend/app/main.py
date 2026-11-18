"""FastAPI application — the deterministic backend authority.

Layering (docs/ARCHITECTURE.md §3): this module wires HTTP to services. It
contains no business rules, no scope logic and no LLM access.
"""
from __future__ import annotations
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from . import errors
from .api.v1 import router as v1_router
from .config import settings
from .logging_setup import configure

configure()
log = structlog.get_logger()

app = FastAPI(
    title="VAPT Platform API",
    version="0.2.0",
    description=("Agentic web VAPT platform — deterministic backend. Synthetic lab assets only; "
                 "scanner execution is disabled by default and gated by a deterministic "
                 "preflight chain."),
    openapi_url=f"{settings().api_base_path}/openapi.json",
    docs_url=f"{settings().api_base_path}/docs",
)

# The dashboard is served from the edge network / the operator's loopback.
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173",
                                                  "http://localhost:5173",
                                                  "http://127.0.0.1:8000"],
                   allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
app.include_router(v1_router, prefix=settings().api_base_path)


@app.middleware("http")
async def trace_middleware(request: Request, call_next):
    import uuid
    trace = request.headers.get("x-vapt-trace") or uuid.uuid4().hex[:32]
    structlog.contextvars.bind_contextvars(trace_id=trace, path=request.url.path,
                                           method=request.method)
    try:
        response = await call_next(request)
    finally:
        structlog.contextvars.unbind_contextvars("trace_id", "path", "method")
    response.headers["X-Vapt-Trace"] = trace
    return response


@app.exception_handler(errors.Problem)
async def problem_handler(request: Request, exc: errors.Problem) -> JSONResponse:
    trace = request.headers.get("x-vapt-trace")
    log.warning("problem", slug=exc.slug, status=exc.status_code, detail=exc.detail)
    return JSONResponse(status_code=exc.status_code, content=exc.body(trace),
                        media_type="application/problem+json")


@app.on_event("startup")
def startup() -> None:
    s = settings()
    log.info("api_starting", env=s.app_env, bind=f"{s.api_bind_ip}:{s.api_port}",
             scanner_execution_enabled=s.scanner_execution_enabled,
             active_scan_enabled=s.active_scan_enabled,
             dual_control_flag=s.dual_control_available,
             default_adapter=s.default_scanner_adapter, llm_enabled=s.llm_enabled)
