"""Apply user suppressions to findings."""

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from cve_detector.db.models import Advisory, Finding, Project, Suppression


def active_suppressions(session: Session, now: datetime) -> list[Suppression]:
    query = select(Suppression).where(
        or_(Suppression.expires_at.is_(None), Suppression.expires_at > now)
    )
    return list(session.scalars(query.order_by(Suppression.id)))


def find_suppression(
    suppressions: Iterable[Suppression], project_id: int, advisory: Advisory
) -> Suppression | None:
    """The first suppression of the advisory (by id or alias) for the project or global."""
    refs = {advisory.source_id.upper(), *(alias.upper() for alias in advisory.aliases)}
    for suppression in suppressions:
        if suppression.project_id not in (None, project_id):
            continue
        if suppression.advisory_ref.strip().upper() in refs:
            return suppression
    return None


def apply_suppressions(
    project: Project, findings: Iterable[Finding], suppressions: Sequence[Suppression]
) -> None:
    """Link each finding to its active suppression, if any.

    A suppressed finding forgets what was notified about it, so that it is reported
    again as new when the suppression expires or is removed.
    """
    for finding in findings:
        suppression = find_suppression(suppressions, project.id, finding.advisory)
        finding.suppression = suppression
        if suppression is not None:
            finding.notified_state = None


def expiring_suppressions(
    suppressions: Iterable[Suppression], project_id: int, now: datetime, window: timedelta
) -> list[Suppression]:
    """Active suppressions affecting the project that expire within ``window``."""
    return [
        s
        for s in suppressions
        if s.project_id in (None, project_id)
        and s.expires_at is not None
        and now < s.expires_at <= now + window
    ]


def refresh_suppressions(session: Session, now: datetime) -> None:
    """Re-link every finding to its active suppression, e.g. after one is added or removed."""
    suppressions = active_suppressions(session, now)
    for project in session.scalars(select(Project)):
        findings = [f for d in project.dependencies for f in d.findings]
        apply_suppressions(project, findings, suppressions)
