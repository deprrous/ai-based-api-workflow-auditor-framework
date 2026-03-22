from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from uuid import uuid4

import httpx

from api.app.config import get_settings
from api.app.database import session_scope
from api.app.db_models import AiProviderAuthRecord, AiProviderConfigRecord, AiProviderOAuthStateRecord
from api.repositories.ai_provider_repository import AiProviderRepository
from api.schemas.ai import (
    AiAuthMethod,
    AiOAuthAuthorizationResponse,
    AiProviderAuthStatus,
    AiProviderConfigCreateRequest,
    AiProviderConfigDetail,
    AiProviderConfigSummary,
    AiProviderValidationResult,
)
from api.services.secret_service import secret_service
from orchestrator.providers.registry import get_provider_catalog

OPENAI_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OPENAI_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
OPENAI_TOKEN_URL = "https://auth.openai.com/oauth/token"
OPENAI_OAUTH_SCOPE = "openid profile email offline_access"
OPENAI_AUTH_CLAIM = "https://api.openai.com/auth"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("ascii").rstrip("=")
    return verifier, challenge


def _decode_openai_account_id(access_token: str) -> str | None:
    try:
        parts = access_token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8")
        parsed = json.loads(decoded)
        auth_block = parsed.get(OPENAI_AUTH_CLAIM, {})
        if isinstance(auth_block, dict):
            account_id = auth_block.get("chatgpt_account_id")
            return str(account_id) if account_id else None
    except Exception:
        return None
    return None


def build_openai_authorization_url(*, redirect_uri: str, state: str, code_challenge: str) -> str:
    params = {
        "response_type": "code",
        "client_id": OPENAI_OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": OPENAI_OAUTH_SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": "codex_cli_rs",
    }
    return f"{OPENAI_AUTHORIZE_URL}?{httpx.QueryParams(params)}"


def exchange_openai_authorization_code(*, code: str, verifier: str, redirect_uri: str) -> dict[str, object] | None:
    response = httpx.post(
        OPENAI_TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "client_id": OPENAI_OAUTH_CLIENT_ID,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20.0,
    )
    response.raise_for_status()
    payload = response.json()
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    expires_in = payload.get("expires_in")
    if not access_token or not refresh_token or not isinstance(expires_in, int):
        return None
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": int((_utc_now() + timedelta(seconds=expires_in)).timestamp()),
        "account_id": _decode_openai_account_id(str(access_token)),
    }


def refresh_openai_oauth_secret(secret: dict[str, object]) -> dict[str, object] | None:
    refresh_token = str(secret.get("refresh_token") or "")
    if not refresh_token:
        return None
    response = httpx.post(
        OPENAI_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OPENAI_OAUTH_CLIENT_ID,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20.0,
    )
    response.raise_for_status()
    payload = response.json()
    access_token = payload.get("access_token")
    new_refresh_token = payload.get("refresh_token") or refresh_token
    expires_in = payload.get("expires_in")
    if not access_token or not isinstance(expires_in, int):
        return None
    return {
        **secret,
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "expires_at": int((_utc_now() + timedelta(seconds=expires_in)).timestamp()),
        "account_id": _decode_openai_account_id(str(access_token)) or secret.get("account_id"),
    }


def _catalog_map() -> dict[str, object]:
    return {provider.key: provider for provider in get_provider_catalog().providers}


def _provider_descriptor(provider_key: str):
    descriptor = _catalog_map().get(provider_key)
    if descriptor is None:
        raise ValueError(f"Unknown AI provider: {provider_key}")
    return descriptor


def _oauth_expired(secret: dict[str, object]) -> bool:
    expires_at = secret.get("expires_at")
    if not isinstance(expires_at, int):
        return True
    return expires_at <= int(_utc_now().timestamp())


def _redact_secret(auth_method: AiAuthMethod, secret: dict[str, object]) -> dict[str, object]:
    if auth_method == AiAuthMethod.API_KEY:
        raw = str(secret.get("api_key") or "")
        return {"last4": raw[-4:] if raw else ""}
    if auth_method == AiAuthMethod.OAUTH_BROWSER:
        return {"account_label": str(secret.get("account_label") or "browser-auth")}
    if auth_method == AiAuthMethod.CLOUD_CREDENTIALS:
        return {
            "project_id": str(secret.get("project_id") or ""),
            "client_email": str(secret.get("client_email") or secret.get("service_account_email") or ""),
        }
    return {}


def _auth_record_to_summary(config: AiProviderConfigRecord, auth_record: AiProviderAuthRecord | None) -> AiProviderConfigSummary:
    return AiProviderConfigSummary(
        id=config.id,
        provider_key=config.provider_key,
        provider_kind=config.provider_kind,
        display_name=config.display_name,
        enabled=config.enabled,
        is_default=config.is_default,
        default_model=config.default_model,
        auth_method=AiAuthMethod(auth_record.auth_method) if auth_record else None,
        auth_status=AiProviderAuthStatus(auth_record.status) if auth_record else None,
        redacted_summary=dict(auth_record.redacted_summary_json) if auth_record else {},
    )


def _auth_record_to_detail(config: AiProviderConfigRecord, auth_record: AiProviderAuthRecord | None) -> AiProviderConfigDetail:
    summary = _auth_record_to_summary(config, auth_record)
    return AiProviderConfigDetail(
        **summary.model_dump(),
        validated_at=auth_record.validated_at.isoformat() if auth_record and auth_record.validated_at else None,
        last_error=auth_record.last_error if auth_record else None,
        created_at=config.created_at.isoformat(),
        updated_at=config.updated_at.isoformat(),
    )


class AiAuthService:
    def list_configs(self) -> list[AiProviderConfigSummary]:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            configs = repository.list_configs()
            return [
                _auth_record_to_summary(config, next(iter(repository.list_auth_records(config.id)), None))
                for config in configs
            ]

    def get_config(self, config_id: str) -> AiProviderConfigDetail | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            config = repository.get_config(config_id)
            if config is None:
                return None
            auth_record = next(iter(repository.list_auth_records(config.id)), None)
            return _auth_record_to_detail(config, auth_record)

    def create_config(self, payload: AiProviderConfigCreateRequest) -> AiProviderConfigDetail:
        descriptor = _provider_descriptor(payload.provider_key)
        now = _utc_now()
        with session_scope() as session:
            repository = AiProviderRepository(session)
            if payload.is_default:
                current_default = repository.get_default_config()
                if current_default is not None:
                    current_default.is_default = False
                    current_default.updated_at = now
            record = AiProviderConfigRecord(
                id=f"aip-{uuid4().hex[:12]}",
                provider_key=payload.provider_key,
                provider_kind=getattr(descriptor, "kind").value,
                display_name=payload.display_name or getattr(descriptor, "display_name"),
                enabled=payload.enabled,
                is_default=payload.is_default,
                default_model=payload.default_model,
                created_at=now,
                updated_at=now,
            )
            repository.add_config(record)
            session.flush()
            session.refresh(record)
            return _auth_record_to_detail(record, None)

    def upsert_auth(self, config_id: str, auth_method: AiAuthMethod, secret: dict[str, object]) -> AiProviderConfigDetail | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            config = repository.get_config(config_id)
            if config is None:
                return None

            descriptor = _provider_descriptor(config.provider_key)
            supported = {method.method for method in getattr(descriptor, "auth_methods")}
            if auth_method not in supported:
                raise ValueError(f"Provider {config.provider_key} does not support auth method {auth_method.value}")

            now = _utc_now()
            auth_record = repository.get_auth_record(config_id, auth_method.value)
            encrypted_secret = secret_service.encrypt_json(secret)
            redacted_summary = _redact_secret(auth_method, secret)
            if auth_record is None:
                auth_record = AiProviderAuthRecord(
                    id=f"aia-{uuid4().hex[:12]}",
                    provider_config_id=config_id,
                    auth_method=auth_method.value,
                    status=AiProviderAuthStatus.CONFIGURED.value,
                    encrypted_secret_json=encrypted_secret,
                    redacted_summary_json=redacted_summary,
                    validated_at=None,
                    last_error=None,
                    created_at=now,
                    updated_at=now,
                )
                repository.add_auth_record(auth_record)
            else:
                auth_record.encrypted_secret_json = encrypted_secret
                auth_record.redacted_summary_json = redacted_summary
                auth_record.status = AiProviderAuthStatus.CONFIGURED.value
                auth_record.validated_at = None
                auth_record.last_error = None
                auth_record.updated_at = now

            config.updated_at = now
            return _auth_record_to_detail(config, auth_record)

    def validate_config(self, config_id: str) -> AiProviderValidationResult | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            config = repository.get_config(config_id)
            if config is None:
                return None
            auth_records = repository.list_auth_records(config.id)
            auth_record = auth_records[0] if auth_records else None
            if auth_record is None:
                return AiProviderValidationResult(
                    config_id=config.id,
                    provider_key=config.provider_key,
                    auth_method=None,
                    status=AiProviderAuthStatus.INVALID,
                    message="No authentication has been configured for this provider.",
                )

            secret = secret_service.decrypt_json(auth_record.encrypted_secret_json)
            status = AiProviderAuthStatus.VALID
            message = "Provider credentials look structurally valid."
            if auth_record.auth_method == AiAuthMethod.API_KEY.value and not secret.get("api_key"):
                status = AiProviderAuthStatus.INVALID
                message = "API key is missing."
            elif auth_record.auth_method == AiAuthMethod.CLOUD_CREDENTIALS.value and not (secret.get("project_id") or secret.get("credentials_json")):
                status = AiProviderAuthStatus.INVALID
                message = "Cloud credential payload is missing project_id or credentials_json."
            elif auth_record.auth_method == AiAuthMethod.OAUTH_BROWSER.value:
                if config.provider_key == "openai":
                    if not (secret.get("access_token") and secret.get("refresh_token") and secret.get("account_id")):
                        status = AiProviderAuthStatus.INVALID
                        message = "OpenAI browser auth is missing access token, refresh token, or account id."
                    elif _oauth_expired(secret):
                        refreshed = refresh_openai_oauth_secret(secret)
                        if refreshed is None:
                            status = AiProviderAuthStatus.EXPIRED
                            message = "OpenAI browser auth token expired and refresh failed."
                        else:
                            secret = refreshed
                            auth_record.encrypted_secret_json = secret_service.encrypt_json(secret)
                            auth_record.redacted_summary_json = _redact_secret(AiAuthMethod.OAUTH_BROWSER, secret)
                            message = "OpenAI browser auth refreshed successfully."
                elif not (secret.get("oauth_code") or secret.get("access_token") or secret.get("account_label")):
                    status = AiProviderAuthStatus.INVALID
                    message = "OAuth/browser auth payload is incomplete."

            auth_record.status = status.value
            auth_record.validated_at = _utc_now()
            auth_record.last_error = None if status == AiProviderAuthStatus.VALID else message
            auth_record.updated_at = _utc_now()
            config.updated_at = auth_record.updated_at
            return AiProviderValidationResult(
                config_id=config.id,
                provider_key=config.provider_key,
                auth_method=AiAuthMethod(auth_record.auth_method),
                status=status,
                message=message,
            )

    def activate_config(self, config_id: str) -> AiProviderConfigDetail | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            config = repository.get_config(config_id)
            if config is None:
                return None
            current_default = repository.get_default_config()
            now = _utc_now()
            if current_default is not None:
                current_default.is_default = False
                current_default.updated_at = now
            config.is_default = True
            config.enabled = True
            config.updated_at = now
            auth_record = next(iter(repository.list_auth_records(config.id)), None)
            return _auth_record_to_detail(config, auth_record)

    def start_oauth_browser(self, config_id: str) -> AiOAuthAuthorizationResponse | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            config = repository.get_config(config_id)
            if config is None:
                return None
            state = secrets.token_urlsafe(24)
            pkce, challenge = _pkce_pair()
            callback_url = f"{get_settings().ai_oauth_redirect_base_url.rstrip('/')}/{config.provider_key}/oauth/callback"
            record = AiProviderOAuthStateRecord(
                id=f"oauth-{uuid4().hex[:12]}",
                provider_key=config.provider_key,
                provider_config_id=config.id,
                state_token=state,
                pkce_verifier=pkce,
                redirect_uri=callback_url,
                expires_at=_utc_now() + timedelta(minutes=10),
                used_at=None,
                created_at=_utc_now(),
            )
            repository.add_oauth_state(record)
            if config.provider_key == "openai":
                authorization_url = build_openai_authorization_url(
                    redirect_uri=callback_url,
                    state=state,
                    code_challenge=challenge,
                )
            else:
                authorization_url = f"{callback_url}?state={state}&provider={config.provider_key}"
            return AiOAuthAuthorizationResponse(
                provider_key=config.provider_key,
                config_id=config.id,
                authorization_url=authorization_url,
                callback_url=callback_url,
                state=state,
            )

    def finalize_oauth_browser(self, provider_key: str, state: str, code: str, account_label: str | None = None) -> AiProviderConfigDetail | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            oauth_state = repository.get_oauth_state(state)
            if (
                oauth_state is None
                or oauth_state.used_at is not None
                or oauth_state.provider_key != provider_key
                or _coerce_utc(oauth_state.expires_at) < _utc_now()
            ):
                return None
            config = repository.get_config(oauth_state.provider_config_id) if oauth_state.provider_config_id else repository.get_config_by_provider_key(provider_key)
            if config is None:
                return None
            oauth_state.used_at = _utc_now()
            auth_record = repository.get_auth_record(config.id, AiAuthMethod.OAUTH_BROWSER.value)
            now = _utc_now()
            if provider_key == "openai":
                exchanged = exchange_openai_authorization_code(
                    code=code,
                    verifier=oauth_state.pkce_verifier,
                    redirect_uri=oauth_state.redirect_uri,
                )
                if exchanged is None:
                    return None
                secret: dict[str, object] = {
                    **exchanged,
                    "account_label": account_label or "ChatGPT Plus/Pro",
                    "model": config.default_model or "gpt-5.1",
                }
            else:
                secret = {
                    "oauth_code": code,
                    "account_label": account_label or f"{provider_key}-browser-account",
                }
            encrypted_secret = secret_service.encrypt_json(secret)
            redacted_summary = _redact_secret(AiAuthMethod.OAUTH_BROWSER, secret)
            if auth_record is None:
                auth_record = AiProviderAuthRecord(
                    id=f"aia-{uuid4().hex[:12]}",
                    provider_config_id=config.id,
                    auth_method=AiAuthMethod.OAUTH_BROWSER.value,
                    status=AiProviderAuthStatus.CONFIGURED.value,
                    encrypted_secret_json=encrypted_secret,
                    redacted_summary_json=redacted_summary,
                    validated_at=None,
                    last_error=None,
                    created_at=now,
                    updated_at=now,
                )
                repository.add_auth_record(auth_record)
            else:
                auth_record.encrypted_secret_json = encrypted_secret
                auth_record.redacted_summary_json = redacted_summary
                auth_record.status = AiProviderAuthStatus.CONFIGURED.value
                auth_record.validated_at = None
                auth_record.last_error = None
                auth_record.updated_at = now
            config.updated_at = now
            return _auth_record_to_detail(config, auth_record)

    def resolve_runtime_auth(self, provider_key: str | None = None) -> dict[str, object] | None:
        with session_scope() as session:
            repository = AiProviderRepository(session)
            config = repository.get_config_by_provider_key(provider_key) if provider_key else repository.get_default_config()
            if config is None or not config.enabled:
                return None
            auth_record = next(iter(repository.list_auth_records(config.id)), None)
            secret = secret_service.decrypt_json(auth_record.encrypted_secret_json) if auth_record else {}
            if auth_record and auth_record.auth_method == AiAuthMethod.OAUTH_BROWSER.value and config.provider_key == "openai" and _oauth_expired(secret):
                refreshed = refresh_openai_oauth_secret(secret)
                if refreshed is not None:
                    secret = refreshed
                    auth_record.encrypted_secret_json = secret_service.encrypt_json(secret)
                    auth_record.redacted_summary_json = _redact_secret(AiAuthMethod.OAUTH_BROWSER, secret)
                    auth_record.status = AiProviderAuthStatus.VALID.value
                    auth_record.validated_at = _utc_now()
                    auth_record.updated_at = auth_record.validated_at
            return {
                "config": config,
                "auth_record": auth_record,
                "secret": secret,
            }


ai_auth_service = AiAuthService()
