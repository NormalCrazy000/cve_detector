from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from cve_detector.catalog import add_dependency
from cve_detector.db.enums import Ecosystem, FindingStatus, ScanStatus
from cve_detector.db.models import Finding, Project, ScanRun
from cve_detector.db.session import get_sessionmaker
from cve_detector.scanning.diff import ChangeKind, ProjectDigest, mark_notified
from cve_detector.scanning.scan import fail_interrupted_runs, run_scan
from cve_detector.sources.base import PackageRef
from tests.scan_helpers import T0, FakeSource, record


class Recorder:
    """Notifier stand-in: keeps the digests and marks them as delivered."""

    def __init__(self, *, fail: bool = False) -> None:
        self.digests: list[ProjectDigest] = []
        self.fail = fail

    def __call__(self, _session: Session, digest: ProjectDigest) -> None:
        if self.fail:
            raise RuntimeError("smtp down")
        self.digests.append(digest)
        mark_notified(digest)

    def kinds(self) -> list[tuple[ChangeKind, str]]:
        last = self.digests[-1]
        return [(c.kind, c.finding.advisory.source_id) for c in last.changes]


def make_project(session: Session, name: str = "demo-project", **deps: str) -> Project:
    project = Project(name=name)
    session.add(project)
    for package, spec in deps.items():
        add_dependency(session, project, Ecosystem.NPM, package.replace("_", "-"), spec)
    session.commit()
    return project


def findings(session: Session) -> dict[str, Finding]:
    return {f.advisory.source_id: f for f in session.scalars(select(Finding))}


def test_first_scan_reports_every_finding(session: Session) -> None:
    project = make_project(session, example_a="1.2.0", example_b="2.5.0")
    source = FakeSource(record("A-1", "example-a"), record("B-1", "example-b"))
    notify = Recorder()

    run = run_scan(session, [source], now=T0, notify=notify)

    assert run is not None
    assert run.status is ScanStatus.SUCCEEDED
    assert (run.projects_scanned, run.libraries_queried, run.findings_new) == (1, 2, 1)
    assert findings(session)["A-1"].status is FindingStatus.AFFECTED
    assert notify.kinds() == [(ChangeKind.NEW, "A-1")]
    assert project.last_scan_at == T0
    assert project.next_scan_at == T0 + timedelta(hours=24)
    assert project.last_scan_error is None


def test_range_specs_can_be_potentially_affected(session: Session) -> None:
    make_project(session, example_a="^1.5.0")
    run_scan(session, [FakeSource(record("A-1", "example-a", fixed="1.8.0"))], now=T0)

    assert findings(session)["A-1"].status is FindingStatus.POTENTIALLY_AFFECTED


def test_only_due_projects_are_scanned_and_libraries_queried_once(session: Session) -> None:
    make_project(session, "one", example_a="1.0.0")
    make_project(session, "two", example_a="1.1.0")
    later = make_project(session, "later", example_b="1.0.0")
    later.next_scan_at = T0 + timedelta(hours=1)
    session.commit()
    source = FakeSource(record("A-1", "example-a"))

    run = run_scan(session, [source], now=T0)

    assert run is not None
    assert run.projects_scanned == 2
    assert [p.name for p in source.listed[0]] == ["example-a"]
    assert run_scan(session, [source], now=T0) is None


def test_findings_that_no_longer_match_are_resolved(session: Session) -> None:
    make_project(session, example_a="1.2.0")
    source = FakeSource(record("A-1", "example-a"), record("A-2", "example-a"))
    notify = Recorder()
    run_scan(session, [source], now=T0, notify=notify)

    # A-1 is corrected to start after our version, A-2 drops the package.
    source.put(
        record("A-1", "example-a", introduced="1.5.0", modified=T0 + timedelta(days=1)),
        record("A-2", "other-lib", modified=T0 + timedelta(days=1)),
    )
    later = T0 + timedelta(days=2)
    run_scan(session, [source], now=later, notify=notify)

    stored = findings(session)
    assert stored["A-1"].status is FindingStatus.FIXED
    assert stored["A-1"].resolved_at == later
    assert stored["A-2"].status is FindingStatus.FIXED
    assert notify.kinds() == [(ChangeKind.RESOLVED, "A-1"), (ChangeKind.RESOLVED, "A-2")]

    run_scan(session, [source], now=later + timedelta(days=2), notify=notify)
    assert notify.kinds() == []


def test_withdrawn_advisories_close_findings(session: Session) -> None:
    make_project(session, example_a="1.2.0")
    source = FakeSource(record("A-1", "example-a"))
    notify = Recorder()
    run_scan(session, [source], now=T0, notify=notify)

    source.put(record("A-1", "example-a", modified=T0 + timedelta(days=1), withdrawn=T0))
    run_scan(session, [source], now=T0 + timedelta(days=2), notify=notify)

    assert findings(session)["A-1"].status is FindingStatus.WITHDRAWN
    assert notify.kinds() == [(ChangeKind.RESOLVED, "A-1")]


def test_withdrawn_advisories_never_open_findings(session: Session) -> None:
    make_project(session, example_a="1.2.0")
    run_scan(session, [FakeSource(record("A-1", "example-a", withdrawn=T0))], now=T0)

    assert findings(session) == {}


def test_reopened_findings_are_reported_as_new(session: Session) -> None:
    make_project(session, example_a="1.2.0")
    source = FakeSource(record("A-1", "example-a"))
    notify = Recorder()
    run_scan(session, [source], now=T0, notify=notify)
    source.put(record("A-1", "example-a", introduced="1.5.0", modified=T0 + timedelta(days=1)))
    run_scan(session, [source], now=T0 + timedelta(days=2), notify=notify)

    source.put(record("A-1", "example-a", modified=T0 + timedelta(days=3)))
    run_scan(session, [source], now=T0 + timedelta(days=4), notify=notify)

    finding = findings(session)["A-1"]
    assert finding.status is FindingStatus.AFFECTED
    assert finding.resolved_at is None
    assert finding.first_seen_at == T0
    assert notify.kinds() == [(ChangeKind.NEW, "A-1")]


def test_scan_requests_made_during_a_scan_are_kept(session: Session) -> None:
    project = make_project(session, example_a="1.0.0")
    requested = T0 + timedelta(minutes=1)

    class RequestDuringScan(FakeSource):
        def list_advisories(self, packages: Sequence[PackageRef]) -> Any:
            # "Scan now" pressed in the UI while the scan is downloading advisories.
            with get_sessionmaker()() as other:
                other.execute(update(Project).values(next_scan_at=requested))
                other.commit()
            return super().list_advisories(packages)

    run_scan(session, [RequestDuringScan()], now=T0)

    assert project.next_scan_at == requested
    assert project.last_scan_at == T0


def test_failed_scan_retries_sooner(session: Session) -> None:
    daily = make_project(session, "daily", example_a="1.0.0")
    hourly = make_project(session, "hourly", example_b="1.0.0")
    hourly.scan_interval_hours = 1
    session.commit()
    source = FakeSource()
    source.fail = True

    run = run_scan(session, [source], now=T0, retry_after=timedelta(hours=2))

    assert run is not None
    assert run.status is ScanStatus.FAILED
    assert run.error == "SourceError: source unavailable"
    assert daily.next_scan_at == T0 + timedelta(hours=2)
    assert hourly.next_scan_at == T0 + timedelta(hours=1)
    assert daily.last_scan_error == run.error
    assert findings(session) == {}


def test_notification_errors_do_not_fail_the_scan(session: Session) -> None:
    make_project(session, example_a="1.0.0")
    source = FakeSource(record("A-1", "example-a"))

    run = run_scan(session, [source], now=T0, notify=Recorder(fail=True))

    assert run is not None
    assert run.status is ScanStatus.SUCCEEDED
    assert findings(session)["A-1"].notified_state is None


def test_interrupted_runs_are_marked_failed(session: Session) -> None:
    session.add(ScanRun(started_at=T0))
    session.commit()

    assert fail_interrupted_runs(session) == 1
    run = session.scalars(select(ScanRun)).one()
    assert (run.status, run.error) == (ScanStatus.FAILED, "interrupted")
