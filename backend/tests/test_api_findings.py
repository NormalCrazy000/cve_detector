from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cve_detector.db.base import utcnow
from cve_detector.db.enums import NotificationKind, Severity
from cve_detector.db.models import NotificationLog
from cve_detector.scanning.scan import run_scan
from tests.scan_helpers import FakeSource, record
from tests.test_api_projects import add_dep, create_project


@pytest.fixture
def scanned(client: TestClient, session: Session) -> dict[str, int]:
    """Two projects sharing a library, scanned once."""
    one = create_project(client, name="one")["id"]
    two = create_project(client, name="two")["id"]
    add_dep(client, one, "example-a", "1.0.0")
    add_dep(client, one, "example-b", "1.0.0")
    add_dep(client, two, "example-a", "1.0.0")
    source = FakeSource(
        record("CRIT-1", "example-a", severity=Severity.CRITICAL, aliases=["CVE-2099-0001"]),
        record("LOW-1", "example-b", severity=Severity.LOW),
        record("OLD-1", "example-b", introduced="0", fixed="0.5.0"),
    )
    run_scan(session, [source], now=utcnow())
    return {"one": one, "two": two}


def findings(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/api/findings", params=params)
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def ids(page: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["project_name"], f["advisory"]["source_id"]) for f in page["items"]]


def test_findings_filters_and_order(client: TestClient, scanned: dict[str, int]) -> None:
    everything = findings(client)
    assert everything["total"] == 3
    assert ids(everything)[-1] == ("one", "LOW-1")
    first = everything["items"][0]
    assert first["advisory"]["severity"] == "critical"
    assert first["advisory"]["url"] == "https://osv.dev/vulnerability/CRIT-1"
    assert first["fixed_versions"] == ["2.0.0"]
    assert first["dependency"]["name"] == "example-a"
    assert first["notified"] is False

    assert ids(findings(client, project_id=scanned["two"])) == [("two", "CRIT-1")]
    assert findings(client, min_severity="high")["total"] == 2
    assert sorted(ids(findings(client, q="cve-2099"))) == [("one", "CRIT-1"), ("two", "CRIT-1")]
    assert findings(client, q="example-b")["total"] == 1
    assert findings(client, status="fixed")["total"] == 0
    page = findings(client, limit=1, offset=1)
    assert (page["total"], len(page["items"])) == (3, 1)


def test_suppressions_apply_immediately(
    client: TestClient, scanned: dict[str, int], session: Session
) -> None:
    created = client.post(
        "/api/suppressions",
        json={
            "advisory_ref": " cve-2099-0001 ",
            "project_id": scanned["one"],
            "reason": "not reachable from our code",
        },
    )
    assert created.status_code == 201
    suppression = created.json()
    assert (suppression["advisory_ref"], suppression["active"]) == ("cve-2099-0001", True)

    suppressed = findings(client, suppressed=True)
    assert ids(suppressed) == [("one", "CRIT-1")]
    assert suppressed["items"][0]["suppression"]["reason"] == "not reachable from our code"
    assert findings(client, suppressed=False)["total"] == 2
    assert client.get(f"/api/projects/{scanned['one']}").json()["open_findings"]["critical"] == 0

    expired = client.patch(
        f"/api/suppressions/{suppression['id']}",
        json={"expires_at": (utcnow() - timedelta(minutes=1)).isoformat()},
    )
    assert expired.json()["active"] is False
    assert findings(client, suppressed=True)["total"] == 0

    listed = client.get("/api/suppressions", params={"project_id": scanned["two"]}).json()
    assert listed == []
    assert client.delete(f"/api/suppressions/{suppression['id']}").status_code == 204
    assert client.delete(f"/api/suppressions/{suppression['id']}").status_code == 404
    missing_project = client.post(
        "/api/suppressions", json={"advisory_ref": "X", "project_id": 999, "reason": "r"}
    )
    assert missing_project.status_code == 404


def test_history_endpoints(client: TestClient, scanned: dict[str, int], session: Session) -> None:
    session.add(
        NotificationLog(
            project_id=scanned["one"],
            kind=NotificationKind.DIGEST,
            channel="email",
            targets=["team@example.com"],
            content_hash="0" * 64,
            success=True,
        )
    )
    session.commit()

    scans = client.get("/api/scans").json()
    log = client.get("/api/notifications/log", params={"project_id": scanned["one"]}).json()

    assert scans["total"] == 1
    assert scans["items"][0]["status"] == "succeeded"
    assert scans["items"][0]["projects_scanned"] == 2
    assert log["total"] == 1
    assert log["items"][0]["targets"] == ["team@example.com"]
    other = client.get("/api/notifications/log", params={"project_id": scanned["two"]}).json()
    assert other["total"] == 0
