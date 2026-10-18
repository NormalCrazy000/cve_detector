from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from cve_detector import __version__
from cve_detector.db.session import get_session

router = APIRouter(tags=["health"])


class Health(BaseModel):
    status: str
    version: str


@router.get("/health")
def health(session: Annotated[Session, Depends(get_session)]) -> Health:
    session.execute(text("SELECT 1"))
    return Health(status="ok", version=__version__)
