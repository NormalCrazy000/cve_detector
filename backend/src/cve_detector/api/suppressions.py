from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.api.deps import DbSession
from cve_detector.api.schemas import SuppressionCreate, SuppressionOut, SuppressionUpdate
from cve_detector.db.base import utcnow
from cve_detector.db.models import Project, Suppression
from cve_detector.scanning.suppressions import refresh_suppressions

router = APIRouter(prefix="/suppressions", tags=["suppressions"])


@router.get("")
def list_suppressions(session: DbSession, project_id: int | None = None) -> list[SuppressionOut]:
    query = select(Suppression).order_by(Suppression.created_at.desc())
    if project_id is not None:
        query = query.where(
            (Suppression.project_id == project_id) | Suppression.project_id.is_(None)
        )
    return [suppression_out(s) for s in session.scalars(query)]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_suppression(body: SuppressionCreate, session: DbSession) -> SuppressionOut:
    if body.project_id is not None and session.get(Project, body.project_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    suppression = Suppression(
        advisory_ref=body.advisory_ref.strip(),
        project_id=body.project_id,
        reason=body.reason,
        expires_at=body.expires_at,
    )
    session.add(suppression)
    _refresh(session)
    return suppression_out(suppression)


@router.patch("/{suppression_id}")
def update_suppression(
    suppression_id: int, body: SuppressionUpdate, session: DbSession
) -> SuppressionOut:
    suppression = _get(session, suppression_id)
    if body.reason is not None:
        suppression.reason = body.reason
    if "expires_at" in body.model_fields_set:
        suppression.expires_at = body.expires_at
    _refresh(session)
    return suppression_out(suppression)


@router.delete("/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_suppression(suppression_id: int, session: DbSession) -> None:
    session.delete(_get(session, suppression_id))
    _refresh(session)


def suppression_out(suppression: Suppression) -> SuppressionOut:
    expires = suppression.expires_at
    return SuppressionOut.model_validate(suppression).model_copy(
        update={"active": expires is None or expires > utcnow()}
    )


def _get(session: Session, suppression_id: int) -> Suppression:
    suppression = session.get(Suppression, suppression_id)
    if suppression is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "suppression not found")
    return suppression


def _refresh(session: Session) -> None:
    """Apply the change to existing findings right away instead of at the next scan."""
    session.flush()
    refresh_suppressions(session, utcnow())
    session.commit()
