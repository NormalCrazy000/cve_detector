import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.core.config import get_settings
from cve_detector.db.models import Finding, Project
from cve_detector.demo import seed_demo


@pytest.fixture
def web_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "web"
    (root / "_app" / "immutable").mkdir(parents=True)
    (root / "200.html").write_text("<html>app</html>")
    (root / "theme.js").write_text("// theme")
    (root / "_app" / "immutable" / "app.123.js").write_text("// app")
    (tmp_path / "secret.txt").write_text("outside")
    monkeypatch.setenv("CVED_WEB_DIR", str(root))
    get_settings.cache_clear()
    return root


def test_web_ui_is_served_next_to_the_api(web_dir: Path, client: TestClient) -> None:
    index = client.get("/projects/3")
    asset = client.get("/_app/immutable/app.123.js")
    plain = client.get("/theme.js")

    assert index.text == "<html>app</html>"
    assert client.head("/").status_code == 200
    assert index.headers["cache-control"] == "no-cache"
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert plain.headers["cache-control"] == "no-cache"
    assert client.get("/../secret.txt").text == "<html>app</html>"
    assert client.get("/%2e%2e/secret.txt").text == "<html>app</html>"
    assert client.get("/api/unknown").status_code == 404
    assert client.get("/api/health").json()["status"] == "ok"


def test_security_headers(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_api_only_without_a_built_ui(client: TestClient) -> None:
    assert client.get("/projects").status_code == 404


def test_demo_dataset(session: Session) -> None:
    seed_demo(session)

    names = sorted(session.scalars(select(Project.name)))
    assert names == ["demo-billing", "demo-internal-tools", "demo-shop"]
    findings = session.scalars(select(Finding)).all()
    assert len(findings) == 7
    assert sum(f.suppression is not None for f in findings) == 1
    assert all(f.advisory.source_id.startswith("DEMO-") for f in findings)


def test_demo_command_refuses_a_used_database(
    db_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    from cve_detector import demo

    assert demo.main() == 0
    assert demo.main() == 1
    assert "already has projects" in capsys.readouterr().err


def test_openapi_export(capsys: pytest.CaptureFixture[str]) -> None:
    from cve_detector import export_openapi

    export_openapi.main()
    schema = json.loads(capsys.readouterr().out)
    assert "/api/findings" in schema["paths"]
    assert "/{path}" not in schema["paths"]


def test_frontend_schema_is_up_to_date() -> None:
    """The TypeScript client is generated from frontend/openapi.json: keep it in sync."""
    from cve_detector.main import create_app

    committed = Path(__file__).resolve().parents[2] / "frontend" / "openapi.json"
    if not committed.exists():
        pytest.skip("frontend not checked out")
    current = create_app().openapi()
    assert json.loads(committed.read_text()) == json.loads(json.dumps(current)), (
        "run: uv run python -m cve_detector.export_openapi > ../frontend/openapi.json "
        "&& (cd ../frontend && npm run gen:api)"
    )
