from __future__ import annotations

from fastapi import APIRouter

from api.app.config import get_settings
from api.schemas.health import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse, summary="Read service health")
async def read_health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
        version=settings.version,
    )
