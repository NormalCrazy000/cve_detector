from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from cve_detector.db.enums import Ecosystem, Severity
from cve_detector.db.models import Dependency, Library, Project


def test_library_is_unique_per_ecosystem(session: Session) -> None:
    session.add(Library(ecosystem=Ecosystem.NPM, name="left-pad"))
    session.add(Library(ecosystem=Ecosystem.MAVEN, name="left-pad"))
    session.commit()

    session.add(Library(ecosystem=Ecosystem.NPM, name="left-pad"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_deleting_project_removes_its_dependencies(session: Session) -> None:
    library = Library(ecosystem=Ecosystem.NPM, name="example-lib")
    project = Project(name="demo-project")
    project.dependencies.append(Dependency(library=library, version_spec="1.0.0", is_exact=True))
    session.add(project)
    session.commit()

    session.delete(project)
    session.commit()

    assert session.scalars(select(Dependency)).all() == []
    assert session.scalars(select(Library)).one().name == "example-lib"


def test_datetimes_are_returned_as_utc(session: Session) -> None:
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    session.add(Project(name="demo-project", next_scan_at=when))
    session.commit()
    session.expunge_all()

    stored = session.scalars(select(Project)).one()
    assert stored.next_scan_at == when
    assert stored.next_scan_at is not None
    assert stored.next_scan_at.tzinfo is UTC


def test_naive_datetimes_are_rejected(session: Session) -> None:
    session.add(Project(name="demo-project", next_scan_at=datetime(2026, 1, 1)))  # noqa: DTZ001
    with pytest.raises(StatementError):
        session.commit()


def test_severity_order() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank > Severity.UNKNOWN.rank
