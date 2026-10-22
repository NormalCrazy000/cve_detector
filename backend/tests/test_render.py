from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.db.enums import NotificationKind, Severity
from cve_detector.db.models import Project, Suppression
from cve_detector.notifiers.base import Message
from cve_detector.notifiers.render import MAX_STILL_OPEN, render_digest, render_notice
from cve_detector.scanning.diff import ProjectDigest, mark_notified
from cve_detector.scanning.scan import run_scan
from tests.scan_helpers import T0, FakeSource, record
from tests.test_scan import make_project

DAY = timedelta(days=1)


def scan(session: Session, source: FakeSource, days: int) -> ProjectDigest:
    """Scan, mark everything as notified and return the digest."""
    digests: list[ProjectDigest] = []

    def notify(_session: Session, digest: ProjectDigest) -> None:
        digests.append(digest)
        mark_notified(digest)

    for project in session.scalars(select(Project)):
        project.next_scan_at = None
    session.commit()
    run_scan(session, [source], now=T0 + days * DAY, notify=notify)
    return digests[0]


def render(digest: ProjectDigest, kind: NotificationKind = NotificationKind.DIGEST) -> Message:
    return render_digest(digest, kind, T0)


@pytest.fixture
def evolving(session: Session) -> ProjectDigest:
    """A digest with one new, one updated, one resolved and one still-open finding."""
    make_project(session, example_a="1.0.0")
    source = FakeSource(
        record("UPD-1", "example-a", severity=Severity.MEDIUM),
        record("RES-1", "example-a"),
        record("OPEN-1", "example-a", severity=Severity.LOW),
    )
    scan(session, source, 0)
    session.add(Suppression(advisory_ref="OLD-1", reason="false positive", expires_at=T0 + 3 * DAY))
    source.put(
        record("NEW-1", "example-a", aliases=["CVE-2099-0001"], modified=T0 + DAY),
        record("UPD-1", "example-a", fixed="1.2.0", modified=T0 + DAY),
        record("RES-1", "example-a", modified=T0 + DAY, withdrawn=T0 + DAY),
    )
    return scan(session, source, 1)


def test_digest_text(evolving: ProjectDigest) -> None:
    message = render(evolving)

    assert message.subject == "[cve_detector] demo-project: 1 new, 1 updated, 1 resolved (2 high)"
    text = message.text
    assert "== NEW (1) ==" in text
    assert "[HIGH 7.5] NEW-1 (CVE-2099-0001)" in text
    assert "Dependency: npm: example-a 1.0.0 (affected)" in text
    assert "Fixed in: 2.0.0" in text
    assert "https://osv.dev/vulnerability/NEW-1" in text
    assert (
        "  Changed: severity: MEDIUM → HIGH\n"
        "  Changed: CVSS score: none → 7.5\n"
        "  Changed: fixed in: 2.0.0 → 1.2.0\n"
    ) in text
    assert "Why: the advisory was withdrawn by its database" in text
    assert "== STILL OPEN (1 low) ==" in text
    assert "[LOW] OPEN-1 - npm: example-a 1.0.0 (affected)" in text
    assert "OLD-1 (all projects) expires 2026-03-04: false positive" in text
    assert "absence of findings does not mean the absence of vulnerabilities" in text


def test_digest_html_escapes_advisory_text(session: Session) -> None:
    make_project(session, example_a="1.0.0")
    digest = scan(session, FakeSource(record("A-1", "example-a")), 0)
    digest.changes[0].finding.advisory.summary = "<script>alert(1)</script>"

    html = render(digest).html

    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "src=" not in html  # no external resources
    assert 'href="https://osv.dev/vulnerability/A-1"' in html


def test_all_clear_without_open_findings(session: Session) -> None:
    make_project(session, example_a="1.0.0")
    digest = scan(session, FakeSource(), 0)

    message = render(digest, NotificationKind.ALL_CLEAR)

    assert message.subject == "[cve_detector] demo-project: no open vulnerabilities"
    assert "No open vulnerabilities" in message.text


def test_long_still_open_lists_are_truncated(session: Session) -> None:
    make_project(session, example_a="1.0.0")
    count = MAX_STILL_OPEN + 3
    digest = scan(session, FakeSource(*(record(f"A-{i:03}", "example-a") for i in range(count))), 0)
    digest.changes.clear()

    message = render(digest, NotificationKind.ALL_CLEAR)
    text = message.text

    assert message.subject.endswith(f"no new issues, {count} still open")
    assert text.count("[HIGH] A-") == MAX_STILL_OPEN
    assert "... and 3 more" in text


def test_notice() -> None:
    message = render_notice("scans are failing", ["Scan 3 failed: <boom>"], T0)

    assert message.subject == "[cve_detector] scans are failing"
    assert "Scan 3 failed: <boom>" in message.text
    assert "Scan 3 failed: &lt;boom&gt;" in message.html
    assert "OSV.dev" not in message.html
