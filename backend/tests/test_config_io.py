from datetime import UTC, datetime

import yaml
from fastapi.testclient import TestClient

from tests.test_api_projects import add_dep, create_project

CONFIG = """
version: 1
projects:
  - name: demo-project
    scan_interval_hours: 12
    min_severity: high
    included_scopes: [runtime]
    recipients: [team@example.com]
    dependencies:
      - {ecosystem: npm, name: example-a, version: 1.0.0}
      - {ecosystem: maven, name: "org.example:lib", version: "[1.0,2.0)", scope: provided}
suppressions:
  - {advisory: CVE-2099-0001, project: demo-project, reason: accepted risk,
     expires: "2027-01-01T00:00:00Z"}
  - {advisory: GHSA-aaaa-bbbb-cccc, reason: false positive}
"""


def import_config(client: TestClient, content: str) -> dict[str, object]:
    response = client.post("/api/config/import", json={"content": content})
    assert response.status_code == 200, response.text
    data: dict[str, object] = response.json()
    return data


def test_import_creates_then_merges(client: TestClient) -> None:
    assert import_config(client, CONFIG) == {
        "projects_created": 1,
        "projects_updated": 0,
        "recipients_added": 1,
        "dependencies_added": 2,
        "suppressions_added": 2,
        "suppressions_updated": 0,
    }
    project = client.get("/api/projects").json()[0]
    assert (project["scan_interval_hours"], project["included_scopes"]) == (12, ["runtime"])

    # Re-importing changes nothing; a local addition survives the merge.
    add_dep(client, project["id"], "local-only", "1.0.0")
    summary = import_config(client, CONFIG)
    assert summary["projects_updated"] == 1
    assert summary["dependencies_added"] == 0
    assert summary["suppressions_updated"] == 2
    names = [d["name"] for d in client.get(f"/api/projects/{project['id']}/dependencies").json()]
    assert sorted(names) == ["example-a", "local-only", "org.example:lib"]


def test_export_round_trip(client: TestClient) -> None:
    project = create_project(client, name="exported", notify_minor_updates=True)
    add_dep(client, project["id"], "example-a", "^1.2.0")
    client.post(f"/api/projects/{project['id']}/recipients", json={"target": "a@example.com"})
    client.post(
        "/api/suppressions",
        json={
            "advisory_ref": "CVE-2099-0002",
            "project_id": project["id"],
            "reason": "r",
            "expires_at": datetime(2027, 1, 1, tzinfo=UTC).isoformat(),
        },
    )

    response = client.get("/api/config/export")

    assert response.headers["content-type"].startswith("application/yaml")
    assert "attachment" in response.headers["content-disposition"]
    document = yaml.safe_load(response.text)
    assert document["projects"][0]["dependencies"][0]["version"] == "^1.2.0"
    assert document["projects"][0]["recipients"] == ["a@example.com"]
    assert document["suppressions"][0]["project"] == "exported"
    assert "password" not in response.text.lower()

    client.delete(f"/api/projects/{project['id']}")
    summary = import_config(client, response.text)
    assert (summary["projects_created"], summary["dependencies_added"]) == (1, 1)
    restored = client.get("/api/projects").json()[0]
    assert restored["notify_minor_updates"] is True


def test_invalid_configurations_change_nothing(client: TestClient) -> None:
    cases = {
        "not: [valid": "invalid YAML",
        "- just a list": "must contain a mapping",
        "version: 2": "unsupported format version",
        "projects: [{name: x, unknown: 1}]": "unknown",
        "projects: [{name: x, recipients: [nope]}]": "invalid recipient",
        "projects: [{name: x}, {name: x}]": "duplicate project names",
        "suppressions: [{advisory: A, project: ghost, reason: r}]": "unknown project",
        "suppressions: [{advisory: A, reason: r, expires: 2027-01-01T00:00:00}]": "timezone",
        "projects: [{name: x, dependencies: [{ecosystem: npm, name: a, version: '>>1'}]}]": "x",
    }
    for content, message in cases.items():
        response = client.post("/api/config/import", json={"content": content})
        assert response.status_code == 422, content
        assert message in response.json()["detail"], (content, response.json())

    assert client.get("/api/projects").json() == []
