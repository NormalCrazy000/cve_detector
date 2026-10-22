from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cve_detector.api.schemas import Page, ScanRunOut
from cve_detector.db.base import utcnow
from cve_detector.db.models import Project, ScanRun
from cve_detector.db.session import get_session

router = APIRouter(tags=["scans"])


class ScanQueued(BaseModel):
    project_id: int
    queued: bool


@router.post("/projects/{project_id}/scan", status_code=status.HTTP_202_ACCEPTED)
def scan_now(
    project_id: int, request: Request, session: Annotated[Session, Depends(get_session)]
) -> ScanQueued:
    """Make the project due now; it is scanned right away, or after the running scan."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    project.next_scan_at = utcnow()
    session.commit()
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is not None:
        scheduler.trigger()
    return ScanQueued(project_id=project_id, queued=True)


@router.get("/scans")
def list_scans(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ScanRunOut]:
    total = session.scalar(select(func.count()).select_from(ScanRun)) or 0
    runs = session.scalars(select(ScanRun).order_by(ScanRun.id.desc()).limit(limit).offset(offset))
    return Page(items=[ScanRunOut.model_validate(r) for r in runs], total=total)
