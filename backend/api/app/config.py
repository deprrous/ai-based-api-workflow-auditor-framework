from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
import os

DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)


def _read_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_csv(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default

    items = tuple(item.strip() for item in value.split(",") if item.strip())
    return items or default


def _read_float(value: str | None, default: float) -> float:
    if value is None:
        return default

    try:
        return float(value)
    except ValueError:
        return default


def _read_json_object(value: str | None, default: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    if value is None:
        return default

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return default

    if not isinstance(parsed, dict):
        return default

    normalized: dict[str, dict[str, str]] = {}
    for key, item in parsed.items():
        if not isinstance(key, str) or not isinstance(item, dict):
            continue
        normalized[key] = {
            str(header_key): str(header_value)
            for header_key, header_value in item.items()
            if isinstance(header_key, str)
        }
    return normalized or default


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str
    environment: str
    version: str
    debug: bool
    api_prefix: str
    cors_origins: tuple[str, ...]
    database_url: str
    database_auto_create: bool
    seed_data: bool
    sse_poll_interval: float
    ingest_tokens: tuple[str, ...]
    admin_tokens: tuple[str, ...]
    verifier_autorun_enabled: bool
    verifier_autorun_mode: str
    verifier_autorun_poll_interval: float
    verifier_autorun_worker_id: str
    verifier_replay_base_url: str | None
    verifier_replay_timeout: float
    verifier_replay_verify_tls: bool
    verifier_replay_actor_headers: dict[str, dict[str, str]]
    replay_artifact_retention_hours: float
    replay_artifact_retention_autorun_enabled: bool
    replay_artifact_retention_poll_interval: float
    replay_artifact_redact_headers: tuple[str, ...]
    replay_artifact_redact_body_keys: tuple[str, ...]
    ai_default_provider: str
    ai_openai_compatible_base_url: str | None
    ai_openai_compatible_api_key: str | None
    ai_openai_compatible_model: str | None
    ai_openai_compatible_verify_tls: bool
    callback_public_base_url: str
    callback_expectation_ttl_seconds: int


@lru_cache
def get_settings() -> Settings:
    return Settings(
        app_name=os.getenv("AUDITOR_APP_NAME", "AI API Workflow Auditor"),
        environment=os.getenv("AUDITOR_ENV", "development"),
        version=os.getenv("AUDITOR_VERSION", "0.1.0"),
        debug=_read_bool(os.getenv("AUDITOR_DEBUG"), default=False),
        api_prefix=os.getenv("AUDITOR_API_PREFIX", "/api/v1"),
        cors_origins=_read_csv(
            os.getenv("AUDITOR_CORS_ORIGINS"),
            DEFAULT_CORS_ORIGINS,
        ),
        database_url=os.getenv(
            "AUDITOR_DATABASE_URL",
            "postgresql+psycopg://auditor:auditor@127.0.0.1:5432/auditor",
        ),
        database_auto_create=_read_bool(os.getenv("AUDITOR_DATABASE_AUTO_CREATE"), default=True),
        seed_data=_read_bool(os.getenv("AUDITOR_SEED_DATA"), default=True),
        sse_poll_interval=_read_float(os.getenv("AUDITOR_SSE_POLL_INTERVAL"), default=1.0),
        ingest_tokens=_read_csv(os.getenv("AUDITOR_INGEST_TOKENS"), tuple()),
        admin_tokens=_read_csv(os.getenv("AUDITOR_ADMIN_TOKENS"), tuple()),
        verifier_autorun_enabled=_read_bool(os.getenv("AUDITOR_VERIFIER_AUTORUN_ENABLED"), default=False),
        verifier_autorun_mode=os.getenv("AUDITOR_VERIFIER_AUTORUN_MODE", "disabled"),
        verifier_autorun_poll_interval=_read_float(os.getenv("AUDITOR_VERIFIER_AUTORUN_POLL_INTERVAL"), default=2.0),
        verifier_autorun_worker_id=os.getenv("AUDITOR_VERIFIER_AUTORUN_WORKER_ID", "verifier-autorun"),
        verifier_replay_base_url=os.getenv("AUDITOR_VERIFIER_REPLAY_BASE_URL") or None,
        verifier_replay_timeout=_read_float(os.getenv("AUDITOR_VERIFIER_REPLAY_TIMEOUT"), default=5.0),
        verifier_replay_verify_tls=_read_bool(os.getenv("AUDITOR_VERIFIER_REPLAY_VERIFY_TLS"), default=True),
        verifier_replay_actor_headers=_read_json_object(os.getenv("AUDITOR_VERIFIER_REPLAY_ACTOR_HEADERS_JSON"), default={}),
        replay_artifact_retention_hours=_read_float(os.getenv("AUDITOR_REPLAY_ARTIFACT_RETENTION_HOURS"), default=72.0),
        replay_artifact_retention_autorun_enabled=_read_bool(
            os.getenv("AUDITOR_REPLAY_ARTIFACT_RETENTION_AUTORUN_ENABLED"),
            default=True,
        ),
        replay_artifact_retention_poll_interval=_read_float(
            os.getenv("AUDITOR_REPLAY_ARTIFACT_RETENTION_POLL_INTERVAL"),
            default=300.0,
        ),
        replay_artifact_redact_headers=_read_csv(
            os.getenv("AUDITOR_REPLAY_ARTIFACT_REDACT_HEADERS"),
            ("authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"),
        ),
        replay_artifact_redact_body_keys=_read_csv(
            os.getenv("AUDITOR_REPLAY_ARTIFACT_REDACT_BODY_KEYS"),
            (
                "password",
                "passwd",
                "secret",
                "token",
                "api_key",
                "access_token",
                "refresh_token",
                "client_secret",
                "authorization",
                "cookie",
                "session",
                "jwt",
            ),
        ),
        ai_default_provider=os.getenv("AUDITOR_AI_DEFAULT_PROVIDER", "mock"),
        ai_openai_compatible_base_url=os.getenv("AUDITOR_AI_OPENAI_COMPATIBLE_BASE_URL") or None,
        ai_openai_compatible_api_key=os.getenv("AUDITOR_AI_OPENAI_COMPATIBLE_API_KEY") or None,
        ai_openai_compatible_model=os.getenv("AUDITOR_AI_OPENAI_COMPATIBLE_MODEL") or None,
        ai_openai_compatible_verify_tls=_read_bool(
            os.getenv("AUDITOR_AI_OPENAI_COMPATIBLE_VERIFY_TLS"),
            default=True,
        ),
        callback_public_base_url=os.getenv(
            "AUDITOR_CALLBACK_PUBLIC_BASE_URL",
            "http://127.0.0.1:8000/api/v1/callbacks/public",
        ),
        callback_expectation_ttl_seconds=int(os.getenv("AUDITOR_CALLBACK_EXPECTATION_TTL_SECONDS", "120")),
    )
