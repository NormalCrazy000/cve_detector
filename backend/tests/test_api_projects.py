from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from cve_detector.db.base import utcnow
from cve_detector.db.models import Project
from cve_detector.notifiers.dispatch import Dispatcher
from cve_detector.scanning.diff import ChangeKind
from cve_detector.scanning.scan import run_scan
from tests.scan_helpers import FakeSource, record
from tests.test_notify import FakeNotifier


def create_project(client: TestClient, **fields: Any) -> dict[str, Any]:
    response = client.post("/api/projects", json={"name": "demo-project", **fields})
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


def add_dep(client: TestClient, project_id: int, name: str, spec: str) -> dict[str, Any]:
    response = client.post(
        f"/api/projects/{project_id}/dependencies",
        json={"ecosystem": "npm", "name": name, "version_spec": spec},
    )
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


def test_project_crud(client: TestClient) -> None:
    project = create_project(client, min_severity="high", included_scopes=["runtime", "runtime"])
    assert project["included_scopes"] == ["runtime"]
    assert project["next_scan_at"] is None
    assert project["open_findings"]["high"] == 0

    assert client.post("/api/projects", json={"name": "demo-project"}).status_code == 409
    other = create_project(client, name="other")
    clash = client.patch(f"/api/projects/{other['id']}", json={"name": "demo-project"})
    assert clash.status_code == 409

    updated = client.patch(
        f"/api/projects/{project['id']}",
        json={"scan_interval_hours": 6, "email_delivery": "together", "description": "x"},
    ).json()
    assert (updated["scan_interval_hours"], updated["email_delivery"]) == (6, "together")
    assert updated["min_severity"] == "high"
    assert (
        client.patch(f"/api/projects/{project['id']}", json={"scan_interval_hours": 0}).status_code
        == 422
    )

    assert [p["name"] for p in client.get("/api/projects").json()] == ["demo-project", "other"]
    assert client.delete(f"/api/projects/{other['id']}").status_code == 204
    assert client.get(f"/api/projects/{other['id']}").status_code == 404


def test_recipients(client: TestClient) -> None:
    project_id = create_project(client)["id"]
    url = f"/api/projects/{project_id}/recipients"

    first = client.post(url, json={"target": "team@example.com"})
    duplicate = client.post(url, json={"target": "TEAM@example.com"})
    invalid = client.post(url, json={"target": "not an address"})

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert invalid.status_code == 422
    assert [r["target"] for r in client.get(url).json()] == ["team@example.com"]
    assert client.delete(f"{url}/{first.json()['id']}").status_code == 204
    assert client.delete(f"{url}/{first.json()['id']}").status_code == 404
    assert client.get(f"/api/projects/{project_id}").json()["recipient_count"] == 0


def test_dependencies(client: TestClient, session: Session) -> None:
    project_id = create_project(client)["id"]
    url = f"/api/projects/{project_id}/dependencies"
    dep = add_dep(client, project_id, " example-a ", "^1.2.0")
    add_dep(client, project_id, "example-a", "2.0.0")

    assert (dep["name"], dep["is_exact"], dep["source"]) == ("example-a", False, "manual")
    bad = client.post(url, json={"ecosystem": "npm", "name": "x", "version_spec": "not!a!range"})
    assert bad.status_code == 422

    changed = client.patch(f"{url}/{dep['id']}", json={"version_spec": "1.5.0", "is_direct": None})
    assert changed.json()["version_spec"] == "1.5.0"
    assert changed.json()["is_exact"] is True
    assert changed.json()["is_direct"] is None
    assert client.patch(f"{url}/{dep['id']}", json={"version_spec": "2.0.0"}).status_code == 409
    assert client.patch(f"{url}/999", json={"scope": "development"}).status_code == 404

    # Changes make the project due at the next scheduler tick.
    project = session.get(Project, project_id)
    assert project is not None
    assert project.next_scan_at is not None

    assert client.delete(f"{url}/{dep['id']}").status_code == 204
    assert [d["version_spec"] for d in client.get(url).json()] == ["2.0.0"]


def test_upgrading_a_dependency_reports_the_findings_it_resolved(
    client: TestClient, session: Session
) -> None:
    project_id = create_project(client)["id"]
    client.post(f"/api/projects/{project_id}/recipients", json={"target": "team@example.com"})
    dep = add_dep(client, project_id, "example-a", "1.0.0")
    source = FakeSource(record("A-1", "example-a", fixed="1.4.0"))
    notifier = FakeNotifier()
    dispatcher = Dispatcher({"email": notifier})

    run_scan(session, [source], now=utcnow(), notify=dispatcher)
    listed = client.get(f"/api/projects/{project_id}/dependencies").json()
    assert listed[0]["open_findings"] == 1
    assert client.get(f"/api/projects/{project_id}").json()["open_findings"]["high"] == 1

    client.patch(
        f"/api/projects/{project_id}/dependencies/{dep['id']}", json={"version_spec": "1.4.0"}
    )
    session.expire_all()
    run_scan(session, [source], now=utcnow(), notify=dispatcher)

    message = notifier.sent[-1][1]
    assert message.subject == "[cve_detector] demo-project: 1 resolved"
    assert "npm: example-a 1.4.0 (no longer affected)" in message.text
    assert ChangeKind.RESOLVED.value in message.subject
