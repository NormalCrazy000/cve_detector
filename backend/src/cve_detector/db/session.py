"""Engine, session factory and FastAPI dependency."""

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from cve_detector.core.config import get_settings


def make_engine(url: str) -> Engine:
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        # FastAPI runs sync endpoints in a thread pool.
        connect_args["check_same_thread"] = False
    engine = create_engine(url, connect_args=connect_args)

    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return engine


@lru_cache
def get_engine() -> Engine:
    return make_engine(get_settings().sqlalchemy_url)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_session() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session
