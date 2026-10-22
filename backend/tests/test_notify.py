from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.core.config import get_settings
from cve_detector.db.enums import AllClearPolicy, EmailDelivery, NotificationKind, ScanStatus
from cve_detector.db.models import Finding, NotificationLog, Project, Recipient, ScanRun
from cve_detector.notifiers.base import Delivery, Message
from cve_detector.notifiers.dispatch import AdminAlerter, Dispatcher, message_kind
from cve_detector.scanning.diff import ProjectDigest
from cve_detector.scanning.scan import INTERRUPTED, run_scan
from tests.scan_helpers import T0, FakeSource, record
from tests.smtp_server import smtp_server
from tests.test_scan import make_project

DAY = timedelta(days=1)


class FakeNotifier:
    channel = "email"

    def __init__(self, failing: set[str] | None = None) -> None:
        self.failing = failing or set()
        self.sent: list[tuple[list[str], Message, bool]] = []

    def send(self, targets: list[str], message: Message, *, together: bool) -> list[Delivery]:
        self.sent.append((targets, message, together))
        groups = [targets] if together else [[t] for t in targets]
        return [
            Delivery(g, not self.failing & set(g), "refused" if self.failing & set(g) else None)
            for g in groups
        ]


def with_recipients(project: Project, *targets: str) -> Project:
    project.recipients.extend(Recipient(target=t) for t in targets)
    return project


def scan(session: Session, source: FakeSource, dispatcher: Dispatcher, days: int) -> None:
    for project in session.scalars(select(Project)):
        project.next_scan_at = None
    session.commit()
    run_scan(session, [source], now=T0 + days * DAY, notify=dispatcher)


def logs(session: Session) -> list[NotificationLog]:
    return list(session.scalars(select(NotificationLog).order_by(NotificationLog.id)))


def test_digest_is_sent_and_findings_marked_notified(session: Session) -> None:
    project = with_recipients(make_project(session, example_a="1.0.0"), "a@example.com")
    notifier = FakeNotifier()

    scan(session, FakeSource(record("A-1", "example-a")), Dispatcher({"email": notifier}), 0)

    [(targets, message, together)] = notifier.sent
    assert (targets, together) == (["a@example.com"], False)
    assert message.subject == "[cve_detector] demo-project: 1 new (1 high)"
    assert session.scalars(select(Finding)).one().notified_state is not None
    assert project.last_notified_at is not None
    [log] = logs(session)
    assert (log.kind, log.project_id, log.targets, log.success) == (
        NotificationKind.DIGEST,
        project.id,
        ["a@example.com"],
        True,
    )


def test_delivery_mode_and_partial_failures(session: Session) -> None:
    project = with_recipients(
        make_project(session, example_a="1.0.0"), "a@example.com", "bad@example.com"
    )
    project.email_delivery = EmailDelivery.TOGETHER
    notifier = FakeNotifier(failing={"bad@example.com"})

    scan(session, FakeSource(record("A-1", "example-a")), Dispatcher({"email": notifier}), 0)
    assert notifier.sent[0][2] is True

    project.email_delivery = EmailDelivery.SEPARATE
    session.scalars(select(Finding)).one().notified_state = None  # notify it again
    scan(session, FakeSource(record("A-1", "example-a")), Dispatcher({"email": notifier}), 1)

    assert [(log.targets, log.success) for log in logs(session)[-2:]] == [
        (["a@example.com"], True),
        (["bad@example.com"], False),
    ]
    # One recipient got it: the finding counts as notified.
    assert session.scalars(select(Finding)).one().notified_state is not None


def test_nothing_is_marked_without_a_successful_delivery(session: Session) -> None:
    make_project(session, example_a="1.0.0")
    source = FakeSource(record("A-1", "example-a"))

    scan(session, source, Dispatcher({"email": FakeNotifier()}), 0)  # no recipients
    assert logs(session) == []
    assert session.scalars(select(Finding)).one().notified_state is None

    with_recipients(session.scalars(select(Project)).one(), "a@example.com")
    scan(session, source, Dispatcher({}), 1)  # email not configured
    [log] = logs(session)
    assert (log.success, log.error) == (False, "email is not configured")
    assert session.scalars(select(Finding)).one().notified_state is None

    notifier = FakeNotifier()
    scan(session, source, Dispatcher({"email": notifier}), 2)
    assert notifier.sent[0][1].subject.endswith("1 new (1 high)")


@pytest.mark.parametrize(
    ("policy", "last_notified", "expected"),
    [
        (AllClearPolicy.NEVER, None, None),
        (AllClearPolicy.EVERY_RUN, T0, NotificationKind.ALL_CLEAR),
        (AllClearPolicy.DAILY, None, NotificationKind.ALL_CLEAR),
        (AllClearPolicy.DAILY, T0 - timedelta(hours=23, minutes=55), NotificationKind.ALL_CLEAR),
        (AllClearPolicy.DAILY, T0 - timedelta(hours=12), None),
        (AllClearPolicy.WEEKLY, T0 - 6 * DAY, None),
        (AllClearPolicy.WEEKLY, T0 - 7 * DAY, NotificationKind.ALL_CLEAR),
    ],
)
def test_all_clear_policy(
    policy: AllClearPolicy, last_notified: datetime | None, expected: NotificationKind | None
) -> None:
    project = Project(name="demo-project", all_clear_policy=policy, last_notified_at=last_notified)

    assert message_kind(ProjectDigest(project), T0) is expected


def test_all_clear_report_lists_still_open_findings(session: Session) -> None:
    project = with_recipients(make_project(session, example_a="1.0.0"), "a@example.com")
    project.all_clear_policy = AllClearPolicy.EVERY_RUN
    source = FakeSource(record("A-1", "example-a"))
    notifier = FakeNotifier()
    dispatcher = Dispatcher({"email": notifier})

    scan(session, source, dispatcher, 0)
    scan(session, source, dispatcher, 1)

    message = notifier.sent[-1][1]
    assert message.subject == "[cve_detector] demo-project: no new issues, 1 still open"
    assert "STILL OPEN (1 high)" in message.text
    assert logs(session)[-1].kind is NotificationKind.ALL_CLEAR


def finished_run(session: Session, status: ScanStatus, error: str | None = None) -> ScanRun:
    run = ScanRun(started_at=T0, status=status, error=error)
    session.add(run)
    session.commit()
    return run


def test_admin_is_alerted_once_per_failure_streak(session: Session) -> None:
    notifier = FakeNotifier()
    alert = AdminAlerter({"email": notifier}, "admin@example.com")

    for status, error in [
        (ScanStatus.SUCCEEDED, None),
        (ScanStatus.FAILED, "SourceError: down"),
        (ScanStatus.FAILED, "SourceError: still down"),
        (ScanStatus.FAILED, INTERRUPTED),
        (ScanStatus.SUCCEEDED, None),
        (ScanStatus.SUCCEEDED, None),
    ]:
        alert(session, finished_run(session, status, error))

    # Neither the repeated failure nor the restart in between sends anything.
    assert [message.subject for _, message, _ in notifier.sent] == [
        "[cve_detector] scans are failing",
        "[cve_detector] scans are working again",
    ]
    assert "SourceError: down" in notifier.sent[0][1].text
    assert {log.kind for log in logs(session)} == {NotificationKind.ADMIN_ALERT}


def test_notification_status_endpoint(client: TestClient) -> None:
    assert client.get("/api/notifications/status").json() == {
        "email_configured": False,
        "admin_alerts": False,
    }


def test_test_email_endpoint(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, session: Session
) -> None:
    with smtp_server() as (recorder, port):
        monkeypatch.setenv("CVED_SMTP_HOST", "127.0.0.1")
        monkeypatch.setenv("CVED_SMTP_PORT", str(port))
        monkeypatch.setenv("CVED_SMTP_SECURITY", "none")
        monkeypatch.setenv("CVED_SMTP_FROM", "alerts@example.com")
        monkeypatch.setenv("CVED_ADMIN_EMAIL", "admin@example.com")
        get_settings.cache_clear()

        response = client.post("/api/notifications/test", json={"to": "me@example.com"})
        status = client.get("/api/notifications/status").json()

    assert response.json() == {"success": True, "error": None}
    assert status == {"email_configured": True, "admin_alerts": True}
    assert recorder.received[0].message["Subject"] == "[cve_detector] test email"
    assert logs(session)[0].kind is NotificationKind.TEST
    assert client.post("/api/notifications/test", json={"to": "not-an-address"}).status_code == 422
