from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.app.config import get_settings
from api.app.database import init_database
from api.routers import ai, artifacts, contracts, findings, health, planner, replay_artifacts, reports, scans, service_accounts, verifier_jobs, verifier_runs, workflows
from api.services.replay_artifact_service import build_retention_service
from api.services.scan_service import scan_service
from api.services.verifier_runtime_service import build_runtime_service


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    retention_service = None
    retention_task = None
    runtime_service = None
    runtime_task = None

    if settings.database_auto_create:
        init_database()

    if settings.seed_data:
        scan_service.ensure_seed_data()

    retention_service = build_retention_service(settings=settings)
    if retention_service is not None:
        retention_service.run_once()
        retention_task = asyncio.create_task(retention_service.run_forever())

    if settings.verifier_autorun_enabled:
        runtime_service = build_runtime_service(settings=settings)
        if runtime_service is not None:
            runtime_task = asyncio.create_task(runtime_service.run_forever())

    yield

    if retention_service is not None:
        retention_service.stop()

    if retention_task is not None:
        await retention_task

    if runtime_service is not None:
        runtime_service.stop()

    if runtime_task is not None:
        await runtime_task


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        lifespan=lifespan,
        title=settings.app_name,
        version=settings.version,
        summary="Control plane for workflow-driven API auditing.",
        description=(
            "Foundational FastAPI application for scan orchestration, workflow data, "
            "and developer-facing audit results."
        ),
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        openapi_url=f"{settings.api_prefix}/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", tags=["system"], summary="Read API metadata")
    async def read_root() -> dict[str, str]:
        return {
            "name": settings.app_name,
            "environment": settings.environment,
            "version": settings.version,
            "api_prefix": settings.api_prefix,
        }

    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(ai.router, prefix=settings.api_prefix)
    app.include_router(scans.router, prefix=settings.api_prefix)
    app.include_router(artifacts.router, prefix=settings.api_prefix)
    app.include_router(contracts.router, prefix=settings.api_prefix)
    app.include_router(findings.router, prefix=settings.api_prefix)
    app.include_router(planner.router, prefix=settings.api_prefix)
    app.include_router(replay_artifacts.router, prefix=settings.api_prefix)
    app.include_router(reports.router, prefix=settings.api_prefix)
    app.include_router(service_accounts.router, prefix=settings.api_prefix)
    app.include_router(verifier_jobs.router, prefix=settings.api_prefix)
    app.include_router(verifier_runs.router, prefix=settings.api_prefix)
    app.include_router(workflows.router, prefix=settings.api_prefix)

    return app


app = create_app()
