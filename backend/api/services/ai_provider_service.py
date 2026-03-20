from __future__ import annotations

from api.schemas.ai import AiProviderCatalog
from orchestrator.providers.registry import get_provider_catalog


class AiProviderService:
    def get_catalog(self) -> AiProviderCatalog:
        return get_provider_catalog()


ai_provider_service = AiProviderService()
