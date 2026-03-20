from __future__ import annotations

from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import pytest
from fastapi.testclient import TestClient

from api.app.config import get_settings
from api.app.database import configure_database, dispose_database, init_database
from api.app.main import app
from api.services.store import audit_store


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'auditor-test.db'}"

    monkeypatch.setenv("AUDITOR_DATABASE_URL", database_url)
    monkeypatch.setenv("AUDITOR_DATABASE_AUTO_CREATE", "true")
    monkeypatch.setenv("AUDITOR_SEED_DATA", "true")
    monkeypatch.setenv("AUDITOR_SSE_POLL_INTERVAL", "0.01")
    monkeypatch.setenv("AUDITOR_INGEST_TOKENS", "test-ingest-token")
    monkeypatch.setenv("AUDITOR_ADMIN_TOKENS", "test-admin-token")

    get_settings.cache_clear()
    configure_database(database_url)
    init_database(drop_existing=True)
    audit_store.ensure_seed_data()

    with TestClient(app) as test_client:
        yield test_client

    dispose_database()
    get_settings.cache_clear()
