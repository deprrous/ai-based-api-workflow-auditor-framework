from __future__ import annotations

from fastapi import Header, HTTPException, status

from api.app.config import get_settings
from api.schemas.service_accounts import ServiceAccountScope
from api.services.service_account_service import service_account_service


def _extract_token(authorization: str | None, custom_header: str | None) -> str | None:
    bearer_token: str | None = None
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value:
            bearer_token = value.strip()

    return custom_header or bearer_token


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_ingest_token(
    authorization: str | None = Header(default=None),
    x_auditor_ingest_token: str | None = Header(default=None),
) -> None:
    settings = get_settings()
    token = _extract_token(authorization, x_auditor_ingest_token)

    if token is None:
        raise _unauthorized("Valid ingest token required.")

    if token in settings.ingest_tokens:
        return

    auth_result = service_account_service.authenticate_token(token, required_scope=ServiceAccountScope.INGEST_EVENTS)
    if auth_result is not None:
        return

    raise _unauthorized("Valid ingest token required.")


async def require_admin_token(
    authorization: str | None = Header(default=None),
    x_auditor_admin_token: str | None = Header(default=None),
) -> None:
    settings = get_settings()
    token = _extract_token(authorization, x_auditor_admin_token)

    if token is None:
        raise _unauthorized("Valid admin token required.")

    if token in settings.admin_tokens:
        return

    auth_result = service_account_service.authenticate_token(token, required_scope=ServiceAccountScope.MANAGE_SERVICE_ACCOUNTS)
    if auth_result is not None:
        return

    raise _unauthorized("Valid admin token required.")


async def require_verifier_job_token(
    authorization: str | None = Header(default=None),
    x_auditor_ingest_token: str | None = Header(default=None),
) -> None:
    settings = get_settings()
    token = _extract_token(authorization, x_auditor_ingest_token)

    if token is None:
        raise _unauthorized("Valid verifier job token required.")

    if token in settings.ingest_tokens:
        return

    auth_result = service_account_service.authenticate_token(token, required_scope=ServiceAccountScope.RUN_VERIFIER_JOBS)
    if auth_result is not None:
        return

    raise _unauthorized("Valid verifier job token required.")
