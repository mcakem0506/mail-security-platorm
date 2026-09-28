"""Engine and session management."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from ..config import get_settings


@lru_cache(maxsize=4)
def get_engine(url: str | None = None) -> Engine:
    settings = get_settings()
    dsn = url or settings.database_url
    kwargs: dict[str, object] = {"pool_pre_ping": True, "future": True}
    if dsn.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update(pool_size=settings.db_pool_size, max_overflow=settings.db_max_overflow)
    engine = create_engine(dsn, echo=False, **kwargs)
    if dsn.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_connection, _record):  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


@lru_cache(maxsize=4)
def _session_factory(url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(url), expire_on_commit=False, class_=Session)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency: one session per request, rolled back on error."""
    session = _session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope(url: str | None = None) -> Iterator[Session]:
    session = _session_factory(url)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
