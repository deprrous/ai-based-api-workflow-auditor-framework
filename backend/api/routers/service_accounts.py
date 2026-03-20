from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.app.security import require_admin_token
from api.schemas.service_accounts import CreateServiceAccountRequest, RotateServiceAccountResponse, ServiceAccountSummary, ServiceAccountWithToken
from api.services.service_account_service import service_account_service

router = APIRouter(prefix="/service-accounts", tags=["service-accounts"])


@router.get("", response_model=list[ServiceAccountSummary], summary="List service accounts")
async def list_service_accounts(_: None = Depends(require_admin_token)) -> list[ServiceAccountSummary]:
    return service_account_service.list_service_accounts()


@router.post(
    "",
    response_model=ServiceAccountWithToken,
    status_code=status.HTTP_201_CREATED,
    summary="Create a service account",
)
async def create_service_account(
    payload: CreateServiceAccountRequest,
    _: None = Depends(require_admin_token),
) -> ServiceAccountWithToken:
    try:
        return service_account_service.create_service_account(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post(
    "/{service_account_id}/rotate",
    response_model=RotateServiceAccountResponse,
    summary="Rotate a service account token",
)
async def rotate_service_account(
    service_account_id: str,
    _: None = Depends(require_admin_token),
) -> RotateServiceAccountResponse:
    result = service_account_service.rotate_service_account(service_account_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found.")

    return result


@router.post(
    "/{service_account_id}/revoke",
    response_model=ServiceAccountSummary,
    summary="Revoke a service account",
)
async def revoke_service_account(
    service_account_id: str,
    _: None = Depends(require_admin_token),
) -> ServiceAccountSummary:
    result = service_account_service.revoke_service_account(service_account_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found.")

    return result
