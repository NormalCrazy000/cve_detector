from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import Select, String, case, cast, func, or_, select

from cve_detector.api.deps import DbSession
from cve_detector.api.projects import dependency_out
from cve_detector.api.schemas import AdvisoryOut, FindingOut, Page
from cve_detector.api.suppressions import suppression_out
from cve_detector.db.enums import FindingStatus, Severity
from cve_detector.db.models import Advisory, Dependency, Finding, Library, Project
from cve_detector.matching import fixed_versions

router = APIRouter(prefix="/findings", tags=["findings"])

_OPEN = [FindingStatus.AFFECTED, FindingStatus.POTENTIALLY_AFFECTED]


@router.get("")
def list_findings(
    session: DbSession,
    project_id: int | None = None,
    status: Annotated[list[FindingStatus] | None, Query()] = None,
    min_severity: Severity | None = None,
    suppressed: bool | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingOut]:
    """Findings, most severe first. Defaults to open findings (suppressed included)."""
    query: Select[Finding] = (
        select(Finding)
        .join(Finding.dependency)
        .join(Dependency.library)
        .join(Finding.advisory)
        .where(Finding.status.in_(status or _OPEN))
    )
    if project_id is not None:
        query = query.where(Dependency.project_id == project_id)
    if min_severity is not None:
        allowed = [s for s in Severity if s.rank >= min_severity.rank or s is Severity.UNKNOWN]
        query = query.where(Advisory.severity.in_(allowed))
    if suppressed is not None:
        column = Finding.suppression_id
        query = query.where(column.is_not(None) if suppressed else column.is_(None))
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(
            or_(
                Advisory.source_id.ilike(pattern),
                cast(Advisory.aliases, String).ilike(pattern),
                Advisory.summary.ilike(pattern),
                Library.name.ilike(pattern),
            )
        )
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    # Severity is stored as text: order by its rank, then newest first.
    rank = case(*((Advisory.severity == s, s.rank) for s in Severity), else_=0)
    page = session.scalars(
        query.order_by(rank.desc(), Finding.first_seen_at.desc(), Finding.id)
        .limit(limit)
        .offset(offset)
    )
    return Page(items=[finding_out(f) for f in page], total=total)


def finding_out(finding: Finding) -> FindingOut:
    advisory = finding.advisory
    library: Library = finding.dependency.library
    project: Project = finding.dependency.project
    return FindingOut(
        id=finding.id,
        project_id=project.id,
        project_name=project.name,
        dependency=dependency_out(finding.dependency),
        advisory=AdvisoryOut(
            id=advisory.id,
            source=advisory.source,
            source_id=advisory.source_id,
            url=f"https://osv.dev/vulnerability/{advisory.source_id}",
            aliases=advisory.aliases,
            summary=advisory.summary,
            severity=advisory.severity,
            cvss_score=advisory.cvss_score,
            cvss_vector=advisory.cvss_vector,
            published_at=advisory.published_at,
            modified_at=advisory.modified_at,
            withdrawn_at=advisory.withdrawn_at,
            is_known_exploited=advisory.is_known_exploited,
        ),
        status=finding.status,
        fixed_versions=fixed_versions(library.ecosystem, library.name, advisory.affected),
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        resolved_at=finding.resolved_at,
        suppression=suppression_out(finding.suppression) if finding.suppression else None,
        notified=finding.notified_state is not None,
    )
