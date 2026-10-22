import pytest
from fastapi.testclient import TestClient

from cve_detector.core.config import get_settings
from cve_detector.core.security import LoginThrottle, hash_password, verify_password
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

GOOD = {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}


def test_api_requires_login(anon_client: TestClient) -> None:
    assert anon_client.get("/api/health").status_code == 200
    for path in ("/api/projects", "/api/findings", "/api/suppressions", "/api/auth/me"):
        assert anon_client.get(path).status_code == 401, path


def test_login_sets_a_protected_cookie_and_logout_revokes_it(anon_client: TestClient) -> None:
    response = anon_client.post("/api/auth/login", json=GOOD)

    assert response.json() == {"username": ADMIN_USERNAME}
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=604800" in cookie
    assert "secure" not in cookie
    token = anon_client.cookies["cved_session"]
    assert anon_client.get("/api/auth/me").json() == {"username": ADMIN_USERNAME}

    assert anon_client.post("/api/auth/logout").status_code == 204
    anon_client.cookies.set("cved_session", token)  # a stolen copy no longer works
    assert anon_client.get("/api/auth/me").status_code == 401


def test_wrong_credentials_and_throttling(anon_client: TestClient) -> None:
    wrong_user = anon_client.post("/api/auth/login", json={**GOOD, "username": "root"})
    assert wrong_user.status_code == 401
    for _ in range(4):
        anon_client.post("/api/auth/login", json={**GOOD, "password": "guess"})

    blocked = anon_client.post("/api/auth/login", json=GOOD)

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0


def test_throttle_window() -> None:
    throttle = LoginThrottle(max_failures=2, window_seconds=0.05)
    throttle.failed("1.2.3.4")
    assert throttle.retry_after("1.2.3.4") == 0
    throttle.failed("1.2.3.4")
    assert throttle.retry_after("1.2.3.4") >= 1
    assert throttle.retry_after("5.6.7.8") == 0
    throttle.succeeded("1.2.3.4")
    assert throttle.retry_after("1.2.3.4") == 0


def test_hashed_admin_password(monkeypatch: pytest.MonkeyPatch, anon_client: TestClient) -> None:
    hashed = hash_password("hunter2-but-longer")
    assert verify_password(hashed, "hunter2-but-longer")
    assert not verify_password(hashed, "wrong")
    assert not verify_password("$argon2id$garbage", "x")
    monkeypatch.setenv("CVED_ADMIN_PASSWORD", hashed)
    get_settings.cache_clear()

    ok = anon_client.post("/api/auth/login", json={**GOOD, "password": "hunter2-but-longer"})

    assert ok.status_code == 200


@pytest.mark.parametrize(
    ("password", "message"), [(None, "is not set"), ("change-me", "still the example value")]
)
def test_unusable_admin_password_stops_startup(
    monkeypatch: pytest.MonkeyPatch, db_url: str, password: str | None, message: str
) -> None:
    from cve_detector.main import create_app

    if password is None:
        monkeypatch.delenv("CVED_ADMIN_PASSWORD")
    else:
        monkeypatch.setenv("CVED_ADMIN_PASSWORD", password)
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match=message), TestClient(create_app()):
        pass


def test_cross_site_and_non_json_writes_are_rejected(client: TestClient) -> None:
    body = {"name": "demo-project"}

    cross_site = client.post("/api/projects", json=body, headers={"Origin": "https://evil.example"})
    form = client.post("/api/projects", data={"name": "demo-project"})
    same_origin = client.post("/api/projects", json=body, headers={"Origin": "http://testserver"})

    assert cross_site.status_code == 403
    assert form.status_code == 415
    assert same_origin.status_code == 201


def test_operation_ids_are_unique_function_names(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    ids = [op["operationId"] for path in schema["paths"].values() for op in path.values()]

    assert len(ids) == len(set(ids))
    assert {"login", "list_projects", "list_findings", "import_configuration"} <= set(ids)


@pytest.mark.parametrize(
    ("answers", "code"),
    [(["secret-pass", "secret-pass"], 0), (["secret-pass", "other"], 1), ([""], 1)],
)
def test_hash_password_command(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    answers: list[str],
    code: int,
) -> None:
    from cve_detector import hash_password as command

    replies = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(replies))

    assert command.main() == code
    out = capsys.readouterr().out
    if code == 0:
        value = out.strip().removeprefix("CVED_ADMIN_PASSWORD='").removesuffix("'")
        assert verify_password(value, "secret-pass")
