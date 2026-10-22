"""Scan due projects: sync advisories, update findings and build each project's digest.

All due projects are scanned in one run so that each library is queried once, even
when several projects use it.
"""

import logging
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from cve_detector.advisories import sync_advisories
from cve_detector.db.base import utcnow
from cve_detector.db.enums import FindingStatus, ScanStatus
from cve_detector.db.models import Advisory, Dependency, Finding, Library, Project, ScanRun
from cve_detector.ecosystems.base import VersionSpec
from cve_detector.matching import match
from cve_detector.scanning.diff import ProjectDigest, diff_project
from cve_detector.scanning.suppressions import (
    active_suppressions,
    apply_suppressions,
    expiring_suppressions,
)
from cve_detector.sources.base import VulnSource

logger = logging.getLogger(__name__)

# Receives each project's digest after its findings are committed; it is responsible
# for calling ``mark_notified`` once the recipients were told.
Notify = Callable[[Session, ProjectDigest], None]

# Error of runs left "running" by a previous process.
INTERRUPTED = "interrupted"

DEFAULT_RETRY_AFTER = timedelta(hours=1)
DEFAULT_EXPIRY_WARNING = timedelta(days=7)


def due_projects(session: Session, now: datetime) -> list[Project]:
    query = select(Project).where(or_(Project.next_scan_at.is_(None), Project.next_scan_at <= now))
    return list(session.scalars(query.order_by(Project.id)))


def run_scan(
    session: Session,
    sources: Sequence[VulnSource],
    *,
    now: datetime | None = None,
    notify: Notify | None = None,
    retry_after: timedelta = DEFAULT_RETRY_AFTER,
    expiry_warning: timedelta = DEFAULT_EXPIRY_WARNING,
) -> ScanRun | None:
    """Scan every project that is due; return the run, or None when nothing was due."""
    now = now or utcnow()
    projects = due_projects(session, now)
    if not projects:
        return None
    run = ScanRun(started_at=now)
    session.add(run)
    session.commit()
    logger.info("scan %d started: %d projects", run.id, len(projects))

    try:
        libraries = list(
            {d.library_id: d.library for p in projects for d in p.dependencies}.values()
        )
        advisories = _sync(session, sources, libraries)
        run.libraries_queried = len(libraries)

        suppressions = active_suppressions(session, now)
        digests = []
        for project in projects:
            findings, new = update_findings(session, project, advisories, now)
            apply_suppressions(project, findings, suppressions)
            expiring = expiring_suppressions(suppressions, project.id, now, expiry_warning)
            digests.append(diff_project(project, findings, expiring))
            project.last_scan_at = now
            project.last_scan_error = None
            _reschedule(session, project, now, timedelta(hours=project.scan_interval_hours))
            run.projects_scanned += 1
            run.findings_new += new
        session.commit()
    except Exception as exc:
        logger.exception("scan %d failed", run.id)
        session.rollback()
        _fail(session, run, projects, now, retry_after, f"{type(exc).__name__}: {exc}")
        session.commit()
        return run

    for digest in digests:
        if notify is None:
            continue
        try:
            notify(session, digest)
            session.commit()
        except Exception:
            logger.exception("notification failed for project %d", digest.project.id)
            session.rollback()

    run.status = ScanStatus.SUCCEEDED
    run.finished_at = utcnow()
    session.commit()
    logger.info(
        "scan %d done: %d libraries, %d new findings",
        run.id,
        run.libraries_queried,
        run.findings_new,
    )
    return run


def update_findings(
    session: Session,
    project: Project,
    advisories: dict[int, list[Advisory]],
    now: datetime,
) -> tuple[list[Finding], int]:
    """Match each dependency of the project against its library's advisories.

    Returns all findings of the project (open and resolved) and how many are new.
    Findings are never deleted: those that no longer match become ``fixed``, those
    of withdrawn advisories ``withdrawn``.
    """
    findings: list[Finding] = []
    new = 0
    for dependency in project.dependencies:
        existing = {f.advisory_id: f for f in dependency.findings}
        seen: set[int] = set()
        for advisory in advisories.get(dependency.library_id, []):
            status = _status(dependency, advisory)
            if status is None:
                continue
            seen.add(advisory.id)
            finding = existing.get(advisory.id)
            if finding is None:
                if not status.is_open:
                    continue  # withdrawn before it was ever found
                dependency.findings.append(
                    Finding(advisory=advisory, status=status, first_seen_at=now, last_seen_at=now)
                )
                new += 1
            else:
                _set_status(finding, status, now)
        for advisory_id, finding in existing.items():
            if advisory_id not in seen:
                _set_status(finding, FindingStatus.FIXED, now)
        findings.extend(dependency.findings)
    session.flush()
    return findings, new


def fail_interrupted_runs(session: Session) -> int:
    """Mark runs left ``running`` by a previous process (crash, restart) as failed."""
    result = session.execute(
        update(ScanRun)
        .where(ScanRun.status == ScanStatus.RUNNING)
        .values(status=ScanStatus.FAILED, finished_at=utcnow(), error=INTERRUPTED)
    )
    session.commit()
    return int(getattr(result, "rowcount", 0) or 0)


def _sync(
    session: Session, sources: Sequence[VulnSource], libraries: list[Library]
) -> dict[int, list[Advisory]]:
    advisories: dict[int, list[Advisory]] = defaultdict(list)
    for source in sources:
        for library_id, found in sync_advisories(session, source, libraries).items():
            advisories[library_id].extend(found)
    return advisories


def _status(dependency: Dependency, advisory: Advisory) -> FindingStatus | None:
    library = dependency.library
    status = match(
        library.ecosystem,
        library.name,
        VersionSpec(dependency.version_spec, dependency.is_exact),
        advisory.affected,
    )
    if status is not None and advisory.withdrawn_at is not None:
        return FindingStatus.WITHDRAWN
    return status


def _set_status(finding: Finding, status: FindingStatus, now: datetime) -> None:
    if status.is_open:
        finding.last_seen_at = now
        finding.resolved_at = None
    elif finding.status.is_open:
        finding.resolved_at = now
    finding.status = status


def _reschedule(session: Session, project: Project, now: datetime, delay: timedelta) -> None:
    """Set the next scan, unless a new one was requested while this one was running."""
    session.execute(
        update(Project)
        .where(
            Project.id == project.id,
            or_(Project.next_scan_at.is_(None), Project.next_scan_at <= now),
        )
        .values(next_scan_at=now + delay)
        .execution_options(synchronize_session=False)
    )
    session.expire(project, ["next_scan_at"])


def _fail(
    session: Session,
    run: ScanRun,
    projects: list[Project],
    now: datetime,
    retry_after: timedelta,
    error: str,
) -> None:
    run.status = ScanStatus.FAILED
    run.finished_at = utcnow()
    run.error = error
    for project in projects:
        project.last_scan_at = now
        project.last_scan_error = error
        delay = min(retry_after, timedelta(hours=project.scan_interval_hours))
        _reschedule(session, project, now, delay)
