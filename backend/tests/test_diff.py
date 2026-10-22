from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.catalog import add_dependency
from cve_detector.db.enums import DependencyScope, Ecosystem, Severity
from cve_detector.db.models import Finding, Project, Suppression
from cve_detector.scanning.diff import ChangeKind
from cve_detector.scanning.scan import run_scan
from tests.scan_helpers import T0, FakeSource, record
from tests.test_scan import Recorder, make_project

DAY = timedelta(days=1)


def scan(session: Session, source: FakeSource, notify: Recorder, days: int) -> None:
    """Scan every project as if ``days`` days had passed since T0."""
    for project in session.scalars(select(Project)):
        project.next_scan_at = None
    session.commit()
    run_scan(session, [source], now=T0 + days * DAY, notify=notify)


def test_threshold_filters_notifications_but_keeps_findings(session: Session) -> None:
    project = make_project(session, example_a="1.0.0")
    project.min_severity = Severity.HIGH
    session.commit()
    source = FakeSource(
        record("LOW-1", "example-a", severity=Severity.LOW),
        record("HIGH-1", "example-a", severity=Severity.HIGH),
        record("UNK-1", "example-a", severity=Severity.UNKNOWN),
    )
    notify = Recorder()

    scan(session, source, notify, 0)

    assert len(session.scalars(select(Finding)).all()) == 3
    assert notify.kinds() == [(ChangeKind.NEW, "HIGH-1"), (ChangeKind.NEW, "UNK-1")]
    assert len(notify.digests[0].open_findings) == 2

    project.min_severity = Severity.LOW
    scan(session, source, notify, 1)
    assert notify.kinds() == [(ChangeKind.NEW, "LOW-1")]


def test_excluded_scopes_are_not_notified(session: Session) -> None:
    project = make_project(session, example_a="1.0.0")
    add_dependency(
        session, project, Ecosystem.NPM, "example-dev", "1.0.0", scope=DependencyScope.DEVELOPMENT
    )
    project.included_scopes = [DependencyScope.RUNTIME.value]
    session.commit()
    source = FakeSource(record("A-1", "example-a"), record("D-1", "example-dev"))
    notify = Recorder()

    scan(session, source, notify, 0)

    assert notify.kinds() == [(ChangeKind.NEW, "A-1")]


def test_significant_changes_are_reported_as_updates(session: Session) -> None:
    make_project(session, example_a="1.0.0")
    source = FakeSource(record("A-1", "example-a", severity=Severity.MEDIUM))
    notify = Recorder()
    scan(session, source, notify, 0)

    source.put(record("A-1", "example-a", fixed="1.5.0", modified=T0 + DAY))
    scan(session, source, notify, 1)

    change = notify.digests[-1].changes[0]
    assert change.kind is ChangeKind.UPDATED
    assert change.changed_fields == ["cvss_score", "fixed_versions", "modified", "severity"]
    assert change.previous is not None
    assert change.previous["fixed_versions"] == ["2.0.0"]
    assert change.state["fixed_versions"] == ["1.5.0"]

    scan(session, source, notify, 2)
    assert notify.kinds() == []


def test_minor_changes_follow_the_project_setting(session: Session) -> None:
    make_project(session, "quiet", example_a="1.0.0")
    chatty = make_project(session, "chatty", example_a="1.0.0")
    chatty.notify_minor_updates = True
    session.commit()
    source = FakeSource(record("A-1", "example-a"))
    notify = Recorder()
    scan(session, source, notify, 0)

    source.put(record("A-1", "example-a", modified=T0 + DAY))  # e.g. a new reference link
    scan(session, source, notify, 1)

    by_project = {d.project.name: [c.kind for c in d.changes] for d in notify.digests[-2:]}
    assert by_project == {"quiet": [], "chatty": [ChangeKind.UPDATED]}


def test_suppressed_findings_return_as_new_when_the_suppression_expires(
    session: Session,
) -> None:
    make_project(session, example_a="1.0.0")
    source = FakeSource(record("GHSA-aaaa", "example-a", aliases=["CVE-2099-0001"]))
    notify = Recorder()
    scan(session, source, notify, 0)

    session.add(
        Suppression(advisory_ref="cve-2099-0001", reason="not reachable", expires_at=T0 + 3 * DAY)
    )
    session.commit()
    scan(session, source, notify, 1)
    finding = session.scalars(select(Finding)).one()
    assert finding.suppression is not None
    assert finding.notified_state is None
    assert notify.kinds() == []
    assert [s.reason for s in notify.digests[-1].expiring_suppressions] == ["not reachable"]

    scan(session, source, notify, 4)
    assert finding.suppression is None
    assert notify.kinds() == [(ChangeKind.NEW, "GHSA-aaaa")]


def test_project_suppressions_do_not_affect_other_projects(session: Session) -> None:
    one = make_project(session, "one", example_a="1.0.0")
    make_project(session, "two", example_a="1.0.0")
    session.add(Suppression(advisory_ref="A-1", project_id=one.id, reason="accepted risk"))
    session.commit()
    notify = Recorder()

    scan(session, FakeSource(record("A-1", "example-a")), notify, 0)

    by_project = {d.project.name: len(d.changes) for d in notify.digests}
    assert by_project == {"one": 0, "two": 1}
    assert not notify.digests[0].has_news
