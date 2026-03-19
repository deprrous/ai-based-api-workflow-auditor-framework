from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
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
    )
