"""Shared API dependencies: database session, admin authentication, request checks."""

from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import RequestResponseEndpoint

from cve_detector.core.security import token_hash
from cve_detector.db.base import utcnow
from cve_detector.db.models import AdminSession
from cve_detector.db.session import get_session

SESSION_COOKIE = "cved_session"
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

DbSession = Annotated[Session, Depends(get_session)]


def current_session(request: Request, session: DbSession) -> AdminSession | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return session.scalars(
        select(AdminSession).where(
            AdminSession.token_hash == token_hash(token), AdminSession.expires_at > utcnow()
        )
    ).one_or_none()


def require_admin(
    admin: Annotated[AdminSession | None, Depends(current_session)],
) -> AdminSession:
    if admin is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "login required")
    return admin


async def reject_cross_site(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Second line of defense against cross-site requests (the cookie is SameSite=Strict).

    State-changing API calls must come from the same origin and carry JSON: browsers
    cannot send JSON cross-site without a CORS preflight, which this app never grants.
    """
    if request.method in _UNSAFE_METHODS and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "cross-site request"}, status.HTTP_403_FORBIDDEN)
        has_body = request.headers.get("content-length", "0") != "0" or (
            "transfer-encoding" in request.headers
        )
        content_type = request.headers.get("content-type", "").split(";")[0].strip()
        if has_body and content_type != "application/json":
            return JSONResponse(
                {"detail": "expected application/json"},
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
    return await call_next(request)
