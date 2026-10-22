import json
from typing import Any

from fastapi.testclient import TestClient

from tests.test_api_projects import add_dep, create_project


def package_json(dependencies: dict[str, str], dev: dict[str, str] | None = None) -> str:
    return json.dumps(
        {"name": "demo-app", "dependencies": dependencies, "devDependencies": dev or {}}
    )


POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.example</groupId><artifactId>known</artifactId>
      <version>2.1.0</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>from-parent</artifactId></dependency>
  </dependencies>
</project>"""


def manifest(client: TestClient, project_id: int, action: str, **body: Any) -> Any:
    return client.post(f"/api/projects/{project_id}/manifest/{action}", json=body)


def deps(client: TestClient, project_id: int) -> list[tuple[str, str, str]]:
    return [
        (d["name"], d["version_spec"], d["source"])
        for d in client.get(f"/api/projects/{project_id}/dependencies").json()
    ]


def test_first_import_previews_then_applies(client: TestClient) -> None:
    project_id = create_project(client)["id"]
    content = package_json({"example-a": "1.0.0", "example-b": "^2.0.0"}, {"example-dev": "3.0.0"})

    preview = manifest(client, project_id, "preview", filename="package.json", content=content)

    assert preview.status_code == 200
    assert [(e["name"], e["scope"]) for e in preview.json()["added"]] == [
        ("example-a", "runtime"),
        ("example-b", "runtime"),
        ("example-dev", "development"),
    ]
    assert deps(client, project_id) == []

    applied = manifest(client, project_id, "apply", filename="package.json", content=content)
    assert applied.status_code == 200
    assert len(deps(client, project_id)) == 3


def test_reimport_synchronizes_only_its_own_source(client: TestClient) -> None:
    project_id = create_project(client)["id"]
    first = package_json({"example-a": "1.0.0", "moment-like": "2.0.0", "example-c": "1.0.0"})
    manifest(client, project_id, "apply", filename="package.json", content=first)
    add_dep(client, project_id, "manual-lib", "1.0.0")
    add_dep(client, project_id, "example-c", "1.1.0")  # same library, entered by hand

    second = package_json({"example-a": "1.4.0", "example-new": "1.0.0", "example-c": "1.1.0"})
    preview = manifest(
        client, project_id, "preview", filename="app/package.json", content=second
    ).json()

    assert [(e["name"], e["previous_spec"], e["version_spec"]) for e in preview["changed"]] == [
        ("example-a", "1.0.0", "1.4.0")
    ]
    assert [e["name"] for e in preview["added"]] == ["example-new"]
    assert sorted(e["name"] for e in preview["removed"]) == ["example-c", "moment-like"]
    assert preview["skipped"] == ["example-c 1.1.0"]

    manifest(client, project_id, "apply", filename="package.json", content=second)

    assert sorted(deps(client, project_id)) == [
        ("example-a", "1.4.0", "package.json"),
        ("example-c", "1.1.0", "manual"),
        ("example-new", "1.0.0", "package.json"),
        ("manual-lib", "1.0.0", "manual"),
    ]
    again = manifest(client, project_id, "preview", filename="package.json", content=second).json()
    assert (again["added"], again["changed"], again["removed"], again["unchanged"]) == (
        [],
        [],
        [],
        2,
    )


def test_scope_changes_are_updates(client: TestClient) -> None:
    project_id = create_project(client)["id"]
    manifest(
        client, project_id, "apply", filename="package.json", content=package_json({"lib": "1.0.0"})
    )

    moved = package_json({}, {"lib": "1.0.0"})
    preview = manifest(client, project_id, "preview", filename="package.json", content=moved).json()

    assert [(e["name"], e["scope"], e["previous_spec"]) for e in preview["changed"]] == [
        ("lib", "development", "1.0.0")
    ]


def test_unresolved_versions_must_be_completed_or_skipped(client: TestClient) -> None:
    project_id = create_project(client)["id"]
    body = {"filename": "pom.xml", "content": POM}

    preview = manifest(client, project_id, "preview", **body).json()
    assert [e["name"] for e in preview["unresolved"]] == ["org.example:from-parent"]
    assert preview["unresolved"][0]["problem"]

    missing = manifest(client, project_id, "apply", **body)
    assert missing.status_code == 422
    assert "org.example:from-parent" in missing.json()["detail"]

    bad = manifest(client, project_id, "apply", **body, resolved={"org.example:from-parent": "]["})
    assert bad.status_code == 422

    completed = manifest(
        client, project_id, "apply", **body, resolved={"org.example:from-parent": "3.0.0"}
    )
    assert completed.status_code == 200
    assert ("org.example:from-parent", "3.0.0", "pom.xml") in deps(client, project_id)

    other = create_project(client, name="other")["id"]
    skipped = manifest(client, other, "apply", **body, skip=["org.example:from-parent"])
    assert skipped.status_code == 200
    assert deps(client, other) == [("org.example:known", "2.1.0", "pom.xml")]


def test_format_detection_and_errors(client: TestClient) -> None:
    project_id = create_project(client)["id"]
    listing = "[INFO]    org.example:listed:jar:1.2.3:compile\n"

    unknown = manifest(client, project_id, "preview", filename="deps.txt", content=listing)
    explicit = manifest(
        client,
        project_id,
        "preview",
        filename="deps.txt",
        content=listing,
        source="mvn-dependency-list",
    )
    broken = manifest(client, project_id, "preview", filename="package.json", content="{")

    assert unknown.status_code == 422
    assert "choose it explicitly" in unknown.json()["detail"]
    assert [e["name"] for e in explicit.json()["added"]] == ["org.example:listed"]
    assert broken.status_code == 422
