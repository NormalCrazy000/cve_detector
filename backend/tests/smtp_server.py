"""A local SMTP server (aiosmtpd) that records the messages it receives."""

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, Envelope, LoginPassword, Session

USERNAME = "alerts@example.com"
PASSWORD = "test-password"  # noqa: S105 - synthetic credentials of the fake server


@dataclass
class Received:
    recipients: list[str]
    message: Message


@dataclass
class Recorder:
    refuse: set[str] = field(default_factory=set)
    received: list[Received] = field(default_factory=list)

    async def handle_RCPT(
        self, server: Any, session: Session, envelope: Envelope, address: str, options: Any
    ) -> str:
        if address in self.refuse:
            return "550 no such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server: Any, session: Session, envelope: Envelope) -> str:
        content = envelope.original_content or b""
        self.received.append(Received(list(envelope.rcpt_tos), message_from_bytes(content)))
        return "250 OK"


def _authenticate(
    server: Any, session: Session, envelope: Envelope, mechanism: str, auth_data: Any
) -> AuthResult:
    ok = isinstance(auth_data, LoginPassword) and (
        auth_data.login.decode(),
        auth_data.password.decode(),
    ) == (USERNAME, PASSWORD)
    # handled=False: let aiosmtpd send the "535 invalid credentials" reply itself.
    return AuthResult(success=ok, handled=False)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@contextmanager
def smtp_server() -> Iterator[tuple[Recorder, int]]:
    recorder = Recorder()
    port = free_port()
    controller = Controller(
        recorder,
        hostname="127.0.0.1",
        port=port,
        authenticator=_authenticate,
        auth_require_tls=False,
    )
    controller.start()
    try:
        yield recorder, port
    finally:
        controller.stop()
