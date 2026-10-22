import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.core.config import get_settings
from cve_detector.db.base import utcnow
from cve_detector.db.enums import ScanStatus
from cve_detector.db.models import Project, ScanRun
from cve_detector.db.session import get_sessionmaker
from cve_detector.main import create_app
from cve_detector.scanning.scheduler import Scheduler
from tests.scan_helpers import FakeSource, record
from tests.test_scan import make_project


def wait_for(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            pytest.fail("condition not met in time")
        time.sleep(0.01)


def scan_runs(session: Session) -> list[ScanRun]:
    session.expire_all()
    return list(session.scalars(select(ScanRun).order_by(ScanRun.id)))


def test_scheduler_scans_due_projects_and_wakes_on_trigger(session: Session) -> None:
    project = make_project(session, example_a="1.0.0")
    source = FakeSource(record("A-1", "example-a"))
    scheduler = Scheduler(get_sessionmaker(), [source], tick_seconds=3600)
    scheduler.start()
    try:
        wait_for(lambda: len(scan_runs(session)) == 1)
        # Like "scan now", possibly while the first run is still finishing.
        project.next_scan_at = utcnow()
        session.commit()
        scheduler.trigger()
        wait_for(lambda: len(scan_runs(session)) == 2)
    finally:
        scheduler.stop()

    assert [r.status for r in scan_runs(session)] == [ScanStatus.SUCCEEDED] * 2


def test_scheduler_fails_runs_interrupted_by_a_restart(session: Session) -> None:
    session.add(ScanRun())
    session.commit()
    scheduler = Scheduler(get_sessionmaker(), [], tick_seconds=3600)
    scheduler.start()
    try:
        with pytest.raises(RuntimeError, match="already started"):
            scheduler.start()
    finally:
        scheduler.stop()

    assert scan_runs(session)[0].error == "interrupted"


def test_scheduler_survives_crashes(monkeypatch: pytest.MonkeyPatch, db_url: str) -> None:
    def broken_factory() -> Session:
        raise RuntimeError("database is gone")

    scheduler = Scheduler(get_sessionmaker(), [])
    monkeypatch.setattr(scheduler, "_session_factory", broken_factory)

    assert scheduler.run_once() is None


def test_scan_now_makes_the_project_due(session: Session, client: TestClient) -> None:
    project = make_project(session, example_a="1.0.0")
    project.next_scan_at = None
    session.commit()

    response = client.post(f"/api/projects/{project.id}/scan")

    assert response.status_code == 202
    assert response.json() == {"project_id": project.id, "queued": True}
    session.expire_all()
    assert session.get(Project, project.id).next_scan_at is not None  # type: ignore[union-attr]
    assert client.post("/api/projects/999/scan").status_code == 404


def test_app_starts_and_stops_the_scheduler(monkeypatch: pytest.MonkeyPatch, db_url: str) -> None:
    source = FakeSource()
    monkeypatch.setenv("CVED_SCHEDULER_ENABLED", "true")
    monkeypatch.setattr("cve_detector.main.make_sources", lambda _settings: [source])
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        assert isinstance(client.app.state.scheduler, Scheduler)  # type: ignore[attr-defined]
    assert source.closed
