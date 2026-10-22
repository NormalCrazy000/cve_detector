from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cve_detector.core.config import get_settings
from cve_detector.db.base import utcnow
from cve_detector.db.enums import NotificationKind
from cve_detector.db.session import get_session
from cve_detector.notifiers import make_notifiers
from cve_detector.notifiers.dispatch import send
from cve_detector.notifiers.render import render_notice

router = APIRouter(prefix="/notifications", tags=["notifications"])


class NotificationStatus(BaseModel):
    email_configured: bool
    admin_alerts: bool


class TestEmail(BaseModel):
    to: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")


class TestResult(BaseModel):
    success: bool
    error: str | None = None


@router.get("/status")
def notification_status() -> NotificationStatus:
    """Which channels are configured; secrets are never returned."""
    settings = get_settings()
    configured = make_notifiers(settings)
    return NotificationStatus(
        email_configured="email" in configured,
        admin_alerts="email" in configured and bool(settings.admin_email),
    )


@router.post("/test")
def send_test_email(
    body: TestEmail, session: Annotated[Session, Depends(get_session)]
) -> TestResult:
    message = render_notice(
        "test email",
        ["This is a test message: email notifications are configured correctly."],
        utcnow(),
    )
    notifiers = make_notifiers(get_settings())
    deliveries = send(session, notifiers, "email", [body.to], message, NotificationKind.TEST)
    session.commit()
    return TestResult(success=deliveries[0].success, error=deliveries[0].error)
