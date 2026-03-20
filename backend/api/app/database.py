from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import get_settings
from api.app.db_models import Base


def _build_engine(database_url: str | None = None) -> Engine:
    settings = get_settings()
    url = database_url or settings.database_url
    connect_args: dict[str, object] = {}

    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(
        url,
        connect_args=connect_args,
        future=True,
        pool_pre_ping=True,
    )


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)


def configure_database(database_url: str | None = None) -> None:
    global engine, SessionLocal

    engine.dispose()
    engine = _build_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)


def init_database(*, drop_existing: bool = False) -> None:
    if drop_existing:
        Base.metadata.drop_all(bind=engine)

    Base.metadata.create_all(bind=engine)


def dispose_database() -> None:
    engine.dispose()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()

    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
