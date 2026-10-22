from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cve_detector.api.schemas import EMAIL_PATTERN, NotificationLogOut, Page
from cve_detector.core.config import get_settings
from cve_detector.db.base import utcnow
from cve_detector.db.enums import NotificationKind
from cve_detector.db.models import NotificationLog
from cve_detector.db.session import get_session
from cve_detector.notifiers import make_notifiers
from cve_detector.notifiers.dispatch import send
from cve_detector.notifiers.render import render_notice

router = APIRouter(prefix="/notifications", tags=["notifications"])


class NotificationStatus(BaseModel):
    email_configured: bool
    admin_alerts: bool


class TestEmail(BaseModel):
    to: str = Field(max_length=320, pattern=EMAIL_PATTERN)


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


@router.get("/log")
def notification_log(
    session: Annotated[Session, Depends(get_session)],
    project_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[NotificationLogOut]:
    query = select(NotificationLog)
    if project_id is not None:
        query = query.where(NotificationLog.project_id == project_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    entries = session.scalars(query.order_by(NotificationLog.id.desc()).limit(limit).offset(offset))
    return Page(items=[NotificationLogOut.model_validate(e) for e in entries], total=total)
