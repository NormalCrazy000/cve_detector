import hmac
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import delete

from cve_detector.api.deps import SESSION_COOKIE, DbSession, current_session, require_admin
from cve_detector.core.config import get_settings
from cve_detector.core.security import LoginThrottle, new_token, token_hash, verify_password
from cve_detector.db.base import utcnow
from cve_detector.db.models import AdminSession

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    username: str
    password: str


class Me(BaseModel):
    username: str


def _throttle(request: Request) -> LoginThrottle:
    throttle: LoginThrottle = request.app.state.login_throttle
    return throttle


@router.post("/login")
def login(credentials: Credentials, request: Request, response: Response, session: DbSession) -> Me:
    settings = get_settings()
    throttle = _throttle(request)
    client = request.client.host if request.client else "unknown"
    if wait := throttle.retry_after(client):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed logins, try again later",
            headers={"Retry-After": str(wait)},
        )
    configured = settings.admin_password.get_secret_value() if settings.admin_password else ""
    # Check both fields every time so that timing does not reveal the username.
    username_ok = hmac.compare_digest(
        settings.admin_username.encode(), credentials.username.encode()
    )
    password_ok = bool(configured) and verify_password(configured, credentials.password)
    if not (username_ok and password_ok):
        throttle.failed(client)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong username or password")
    throttle.succeeded(client)

    now = utcnow()
    session.execute(delete(AdminSession).where(AdminSession.expires_at <= now))
    token = new_token()
    lifetime = timedelta(days=settings.session_days)
    session.add(AdminSession(token_hash=token_hash(token), expires_at=now + lifetime))
    session.commit()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(lifetime.total_seconds()),
        httponly=True,
        samesite="strict",
        secure=settings.cookie_secure,
        path="/",
    )
    return Me(username=settings.admin_username)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    session: DbSession,
    admin: Annotated[AdminSession | None, Depends(current_session)],
) -> None:
    if admin is not None:
        session.delete(admin)
        session.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="strict", httponly=True)


@router.get("/me", dependencies=[Depends(require_admin)])
def me() -> Me:
    return Me(username=get_settings().admin_username)
