"""Email notifier over SMTP (STARTTLS, implicit TLS or plain)."""

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

from cve_detector.core.config import Settings, SmtpSecurity
from cve_detector.notifiers.base import Delivery, Message

logger = logging.getLogger(__name__)


class EmailNotifier:
    channel = "email"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        security: SmtpSecurity,
        sender: str,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._host = host
        self._port = port
        self._security = security
        self._sender = sender
        self._username = username
        self._password = password
        self._timeout = timeout

    @classmethod
    def from_settings(cls, settings: Settings) -> "EmailNotifier | None":
        """None when SMTP is not configured."""
        sender = settings.smtp_from or settings.smtp_username
        if not settings.smtp_host or not sender:
            return None
        return cls(
            host=settings.smtp_host,
            port=settings.smtp_port,
            security=settings.smtp_security,
            sender=sender,
            username=settings.smtp_username,
            password=settings.smtp_password.get_secret_value() if settings.smtp_password else None,
            timeout=settings.smtp_timeout_seconds,
        )

    def send(self, targets: list[str], message: Message, *, together: bool) -> list[Delivery]:
        groups = [targets] if together else [[t] for t in targets]
        try:
            with self._connect() as smtp:
                return [self._send_one(smtp, group, message) for group in groups]
        except (OSError, smtplib.SMTPException) as exc:
            logger.warning("cannot connect to the SMTP server: %s", _describe(exc))
            return [Delivery(group, False, _describe(exc)) for group in groups]

    def _connect(self) -> smtplib.SMTP:
        context = ssl.create_default_context()
        smtp: smtplib.SMTP
        if self._security is SmtpSecurity.SSL:
            smtp = smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout, context=context)
        else:
            smtp = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
        try:
            if self._security is SmtpSecurity.STARTTLS:
                smtp.starttls(context=context)
            if self._username and self._password:
                smtp.login(self._username, self._password)
        except BaseException:
            smtp.close()
            raise
        return smtp

    def _send_one(self, smtp: smtplib.SMTP, targets: list[str], message: Message) -> Delivery:
        email = EmailMessage()
        email["Subject"] = message.subject
        email["From"] = self._sender
        email["To"] = ", ".join(targets)
        email["Date"] = formatdate(localtime=False)
        # Without an explicit domain the local hostname would leak into the header.
        domain = parseaddr(self._sender)[1].partition("@")[2] or "cve-detector.invalid"
        email["Message-ID"] = make_msgid(domain=domain)
        email.set_content(message.text)
        email.add_alternative(message.html, subtype="html")
        try:
            refused = smtp.send_message(email)
        except smtplib.SMTPException as exc:
            logger.debug("email to %s failed: %s", targets, exc)
            return Delivery(targets, False, _describe(exc))
        if refused:
            # Some recipients of a shared message were refused, the others got it.
            return Delivery(targets, True, f"refused: {', '.join(sorted(refused))}")
        return Delivery(targets, True)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"
