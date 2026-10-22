from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cve_detector.core.config import get_settings
from cve_detector.db.migrate import upgrade_to_head
from cve_detector.db.session import get_engine, get_sessionmaker


def _clear_caches() -> None:
    get_settings.cache_clear()
    get_sessionmaker.cache_clear()
    get_engine.cache_clear()


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point every test at its own empty data directory and ignore any local .env."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CVED_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("CVED_DATABASE_URL", raising=False)
    # Never reach OSV from tests; scheduler tests start their own.
    monkeypatch.setenv("CVED_SCHEDULER_ENABLED", "false")
    _clear_caches()
    yield tmp_path / "data"
    get_engine().dispose()
    _clear_caches()


@pytest.fixture
def db_url(isolated_settings: Path) -> str:
    isolated_settings.mkdir(parents=True, exist_ok=True)
    url = get_settings().sqlalchemy_url
    upgrade_to_head(url)
    return url


@pytest.fixture
def session(db_url: str) -> Iterator[Session]:
    with get_sessionmaker()() as s:
        yield s


@pytest.fixture
def client() -> Iterator[TestClient]:
    from cve_detector.main import create_app

    with TestClient(create_app()) as c:
        yield c
