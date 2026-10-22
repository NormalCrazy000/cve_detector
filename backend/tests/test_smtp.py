from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr

from cve_detector.core.config import Settings, SmtpSecurity
from cve_detector.notifiers import make_notifiers
from cve_detector.notifiers.base import Message
from cve_detector.notifiers.smtp import EmailNotifier
from tests.smtp_server import PASSWORD, USERNAME, Recorder, free_port, smtp_server

MESSAGE = Message(subject="hello", text="plain body", html="<p>html body</p>")
A, B = "one@example.com", "two@example.com"


@pytest.fixture
def server() -> Iterator[tuple[Recorder, int]]:
    with smtp_server() as running:
        yield running


def notifier(port: int, **kwargs: Any) -> EmailNotifier:
    options: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "security": SmtpSecurity.NONE,
        "sender": "cve_detector <alerts@example.com>",
        "timeout": 5,
    }
    return EmailNotifier(**(options | kwargs))


def test_separate_messages_keep_recipients_private(server: tuple[Recorder, int]) -> None:
    recorder, port = server

    deliveries = notifier(port).send([A, B], MESSAGE, together=False)

    assert [(d.targets, d.success) for d in deliveries] == [([A], True), ([B], True)]
    assert [r.recipients for r in recorder.received] == [[A], [B]]
    email = recorder.received[0].message
    assert email["To"] == A
    assert email["Subject"] == "hello"
    assert email["Message-ID"].endswith("@example.com>")
    parts = {p.get_content_type(): p.get_payload(decode=True) for p in email.walk()}
    assert parts["text/plain"].strip() == b"plain body"  # type: ignore[union-attr]
    assert parts["text/html"].strip() == b"<p>html body</p>"  # type: ignore[union-attr]


def test_together_sends_one_message(server: tuple[Recorder, int]) -> None:
    recorder, port = server

    deliveries = notifier(port).send([A, B], MESSAGE, together=True)

    assert [(d.targets, d.success) for d in deliveries] == [([A, B], True)]
    assert recorder.received[0].recipients == [A, B]
    assert recorder.received[0].message["To"] == f"{A}, {B}"


def test_refused_recipients(server: tuple[Recorder, int]) -> None:
    recorder, port = server
    recorder.refuse.add(B)

    separate = notifier(port).send([A, B], MESSAGE, together=False)
    together = notifier(port).send([A, B], MESSAGE, together=True)

    assert [d.success for d in separate] == [True, False]
    assert separate[1].error is not None
    assert separate[1].error.startswith("SMTPRecipientsRefused")
    assert together[0].success
    assert together[0].error == f"refused: {B}"


def test_login(server: tuple[Recorder, int]) -> None:
    recorder, port = server

    ok = notifier(port, username=USERNAME, password=PASSWORD).send([A], MESSAGE, together=False)
    wrong = notifier(port, username=USERNAME, password="wrong").send(  # noqa: S106
        [A, B], MESSAGE, together=False
    )

    assert ok[0].success
    assert [d.success for d in wrong] == [False, False]
    assert wrong[0].error is not None
    assert wrong[0].error.startswith("SMTPAuthenticationError")
    assert "wrong" not in wrong[0].error
    assert len(recorder.received) == 1


def test_unreachable_server() -> None:
    deliveries = notifier(free_port()).send([A], MESSAGE, together=False)

    assert not deliveries[0].success
    assert deliveries[0].error is not None
    assert deliveries[0].error.startswith("ConnectionRefusedError")


class FakeSmtp:
    """Stands in for smtplib.SMTP; the latest instance is kept in ``last``."""

    last: "FakeSmtp"
    calls: list[str]

    def __init__(self, host: str, port: int, **kwargs: Any) -> None:
        self.calls = [f"connect {type(self).__name__} {host}:{port} tls={'context' in kwargs}"]
        FakeSmtp.last = self

    def starttls(self, **kwargs: Any) -> None:
        self.calls.append("starttls")

    def login(self, username: str, password: str) -> None:
        self.calls.append(f"login {username}")

    def send_message(self, message: Any) -> dict[str, Any]:
        self.calls.append(f"send {message['To']}")
        return {}

    def close(self) -> None:
        self.calls.append("close")

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class FakeSmtpSsl(FakeSmtp):
    pass


@pytest.mark.parametrize(
    ("security", "expected"),
    [
        (SmtpSecurity.STARTTLS, ["connect FakeSmtp smtp.example.com:587 tls=False", "starttls"]),
        (SmtpSecurity.SSL, ["connect FakeSmtpSsl smtp.example.com:587 tls=True"]),
    ],
)
def test_tls_modes(
    monkeypatch: pytest.MonkeyPatch, security: SmtpSecurity, expected: list[str]
) -> None:
    monkeypatch.setattr("smtplib.SMTP", FakeSmtp)
    monkeypatch.setattr("smtplib.SMTP_SSL", FakeSmtpSsl)
    email = EmailNotifier(
        host="smtp.example.com",
        port=587,
        security=security,
        sender="alerts@example.com",
        username=USERNAME,
        password=PASSWORD,
    )

    assert email.send([A], MESSAGE, together=False)[0].success
    assert FakeSmtp.last.calls == [*expected, f"login {USERNAME}", f"send {A}", "close"]


def test_failed_login_closes_the_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    class RejectingSmtp(FakeSmtp):
        def login(self, username: str, password: str) -> None:
            raise OSError("connection reset")

    monkeypatch.setattr("smtplib.SMTP", RejectingSmtp)
    email = notifier(25, username=USERNAME, password=PASSWORD)

    assert not email.send([A], MESSAGE, together=False)[0].success
    assert FakeSmtp.last.calls[-1] == "close"


def test_notifier_from_settings() -> None:
    assert make_notifiers(Settings()) == {}
    assert make_notifiers(Settings(smtp_host="smtp.example.com")) == {}

    configured = make_notifiers(
        Settings(
            smtp_host="smtp.example.com",
            smtp_username=USERNAME,
            smtp_password=SecretStr(PASSWORD),
        )
    )
    assert isinstance(configured["email"], EmailNotifier)
