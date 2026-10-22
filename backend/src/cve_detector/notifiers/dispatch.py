"""Send each project's digest after a scan, and alert the admin about failing scans."""

import hashlib
import logging
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from cve_detector.db.base import utcnow
from cve_detector.db.enums import (
    AllClearPolicy,
    EmailDelivery,
    NotificationKind,
    ScanStatus,
)
from cve_detector.db.models import NotificationLog, Project, ScanRun
from cve_detector.notifiers.base import Delivery, Message, Notifier
from cve_detector.notifiers.render import render_digest, render_notice
from cve_detector.scanning.diff import ProjectDigest, mark_notified
from cve_detector.scanning.scan import INTERRUPTED

logger = logging.getLogger(__name__)

_ALL_CLEAR_PERIODS = {
    AllClearPolicy.DAILY: timedelta(days=1),
    AllClearPolicy.WEEKLY: timedelta(days=7),
}
# Scans drift by a few minutes: a daily report is due slightly before 24 hours.
_ALL_CLEAR_TOLERANCE = timedelta(hours=1)


class Dispatcher:
    """The ``Notify`` callback of the scan engine.

    A digest is sent when something changed; otherwise an all-clear report when the
    project's policy says so. Findings count as notified once at least one recipient
    got the message; failed deliveries are logged and retried with the next digest.
    """

    def __init__(self, notifiers: Mapping[str, Notifier]) -> None:
        self._notifiers = notifiers

    def __call__(self, session: Session, digest: ProjectDigest) -> None:
        project = digest.project
        now = utcnow()
        kind = message_kind(digest, now)
        if kind is None:
            return
        if not project.recipients:
            logger.info("project %d has no recipients, nothing sent", project.id)
            return
        message = render_digest(digest, kind, now)
        targets: dict[str, list[str]] = defaultdict(list)
        for recipient in project.recipients:
            targets[recipient.channel].append(recipient.target)
        together = project.email_delivery is EmailDelivery.TOGETHER
        delivered = False
        for channel, channel_targets in sorted(targets.items()):
            deliveries = send(
                session,
                self._notifiers,
                channel,
                channel_targets,
                message,
                kind,
                project=project,
                together=together,
            )
            delivered |= any(d.success for d in deliveries)
        if delivered:
            mark_notified(digest)
            project.last_notified_at = now


def message_kind(digest: ProjectDigest, now: datetime) -> NotificationKind | None:
    if digest.has_news:
        return NotificationKind.DIGEST
    project = digest.project
    policy = project.all_clear_policy
    if policy is AllClearPolicy.NEVER:
        return None
    if policy is AllClearPolicy.EVERY_RUN or project.last_notified_at is None:
        return NotificationKind.ALL_CLEAR
    due = project.last_notified_at + _ALL_CLEAR_PERIODS[policy] - _ALL_CLEAR_TOLERANCE
    return NotificationKind.ALL_CLEAR if now >= due else None


def send(
    session: Session,
    notifiers: Mapping[str, Notifier],
    channel: str,
    targets: list[str],
    message: Message,
    kind: NotificationKind,
    *,
    project: Project | None = None,
    together: bool = False,
) -> list[Delivery]:
    """Send through a channel and log every delivery attempt."""
    notifier = notifiers.get(channel)
    if notifier is None:
        logger.warning("%s notifications are not configured", channel)
        deliveries = [Delivery(targets, False, f"{channel} is not configured")]
    else:
        deliveries = notifier.send(targets, message, together=together)
    content_hash = hashlib.sha256(f"{message.subject}\n{message.text}".encode()).hexdigest()
    for delivery in deliveries:
        session.add(
            NotificationLog(
                project_id=project.id if project else None,
                kind=kind,
                channel=channel,
                targets=delivery.targets,
                content_hash=content_hash,
                success=delivery.success,
                error=delivery.error,
            )
        )
    failed = sum(not d.success for d in deliveries)
    logger.info(
        "%s via %s: %d sent, %d failed", kind.value, channel, len(deliveries) - failed, failed
    )
    return deliveries


class AdminAlerter:
    """Emails the admin when scans start failing and when they work again.

    Runs interrupted by a restart are ignored, so restarts never cause alerts.
    """

    def __init__(self, notifiers: Mapping[str, Notifier], admin_email: str) -> None:
        self._notifiers = notifiers
        self._admin_email = admin_email

    def __call__(self, session: Session, run: ScanRun) -> None:
        previous = session.scalars(
            select(ScanRun)
            .where(
                ScanRun.id < run.id,
                ScanRun.status != ScanStatus.RUNNING,
                or_(ScanRun.error.is_(None), ScanRun.error != INTERRUPTED),
            )
            .order_by(ScanRun.id.desc())
            .limit(1)
        ).first()
        was_failing = previous is not None and previous.status is ScanStatus.FAILED
        now = utcnow()
        if run.status is ScanStatus.FAILED and not was_failing:
            message = render_notice(
                "scans are failing",
                [
                    f"Scan {run.id} failed: {run.error}",
                    "Scans are retried automatically. You will get another message "
                    "when they work again.",
                ],
                now,
            )
        elif run.status is ScanStatus.SUCCEEDED and was_failing:
            message = render_notice(
                "scans are working again", [f"Scan {run.id} completed successfully."], now
            )
        else:
            return
        send(
            session,
            self._notifiers,
            "email",
            [self._admin_email],
            message,
            NotificationKind.ADMIN_ALERT,
        )
