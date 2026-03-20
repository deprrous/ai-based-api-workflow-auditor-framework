from __future__ import annotations

from fastapi import APIRouter

from api.schemas.ai import AiProviderCatalog
from api.services.ai_provider_service import ai_provider_service

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/providers/catalog", response_model=AiProviderCatalog, summary="Read the provider-neutral AI catalog")
async def get_provider_catalog() -> AiProviderCatalog:
    return ai_provider_service.get_catalog()
