from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from cve_detector.db.base import utcnow
from cve_detector.db.models import Project
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
