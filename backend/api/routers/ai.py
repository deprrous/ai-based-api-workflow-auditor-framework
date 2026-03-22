from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.app.security import require_admin_token
from api.schemas.ai import (
    AiAuthMethod,
    AiOAuthAuthorizationResponse,
    AiProviderAuthUpsertRequest,
    AiProviderCatalog,
    AiProviderConfigCreateRequest,
    AiProviderConfigDetail,
    AiProviderConfigSummary,
    AiProviderValidationResult,
)
from api.services.ai_provider_service import ai_provider_service

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/providers/catalog", response_model=AiProviderCatalog, summary="Read the provider-neutral AI catalog")
async def get_provider_catalog() -> AiProviderCatalog:
    return ai_provider_service.get_catalog()


@router.get("/providers/configs", response_model=list[AiProviderConfigSummary], summary="List AI provider configs")
async def list_provider_configs(_: None = Depends(require_admin_token)) -> list[AiProviderConfigSummary]:
    return ai_provider_service.list_configs()


@router.post("/providers/configs", response_model=AiProviderConfigDetail, status_code=status.HTTP_201_CREATED, summary="Create AI provider config")
async def create_provider_config(payload: AiProviderConfigCreateRequest, _: None = Depends(require_admin_token)) -> AiProviderConfigDetail:
    return ai_provider_service.create_config(payload)


@router.get("/providers/configs/{config_id}", response_model=AiProviderConfigDetail, summary="Read AI provider config")
async def get_provider_config(config_id: str, _: None = Depends(require_admin_token)) -> AiProviderConfigDetail:
    config = ai_provider_service.get_config(config_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI provider config not found.")
    return config


@router.post("/providers/configs/{config_id}/auth", response_model=AiProviderConfigDetail, summary="Upsert AI provider auth")
async def upsert_provider_auth(config_id: str, payload: AiProviderAuthUpsertRequest, _: None = Depends(require_admin_token)) -> AiProviderConfigDetail:
    try:
        config = ai_provider_service.upsert_auth(config_id, payload.auth_method, payload.secret)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI provider config not found.")
    return config


@router.post("/providers/configs/{config_id}/validate", response_model=AiProviderValidationResult, summary="Validate AI provider config")
async def validate_provider_config(config_id: str, _: None = Depends(require_admin_token)) -> AiProviderValidationResult:
    result = ai_provider_service.validate_config(config_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI provider config not found.")
    return result


@router.post("/providers/configs/{config_id}/activate", response_model=AiProviderConfigDetail, summary="Activate AI provider config")
async def activate_provider_config(config_id: str, _: None = Depends(require_admin_token)) -> AiProviderConfigDetail:
    config = ai_provider_service.activate_config(config_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI provider config not found.")
    return config


@router.post("/providers/{provider_key}/oauth/authorize", response_model=AiOAuthAuthorizationResponse, summary="Start provider OAuth/browser auth")
async def authorize_provider_oauth(
    provider_key: str,
    config_id: str = Query(description="Provider config identifier."),
    _: None = Depends(require_admin_token),
) -> AiOAuthAuthorizationResponse:
    config = ai_provider_service.get_config(config_id)
    if config is None or config.provider_key != provider_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI provider config not found for this provider.")
    response = ai_provider_service.start_oauth_browser(config_id)
    if response is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI provider config not found.")
    return response


@router.get("/providers/{provider_key}/oauth/callback", response_model=AiProviderConfigDetail, summary="Finalize provider OAuth/browser auth")
async def finalize_provider_oauth(
    provider_key: str,
    state: str,
    code: str,
    account_label: str | None = None,
) -> AiProviderConfigDetail:
    config = ai_provider_service.finalize_oauth_browser(provider_key, state, code, account_label)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth state or AI provider config not found.")
    return config
