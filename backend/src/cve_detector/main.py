"""FastAPI application entry point: ``uvicorn cve_detector.main:app``."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute

from cve_detector import __version__
from cve_detector.api import (
    auth,
    config,
    findings,
    health,
    notifications,
    projects,
    scans,
    suppressions,
)
from cve_detector.api.deps import reject_cross_site, require_admin
from cve_detector.core.config import get_settings
from cve_detector.core.logging import configure_logging
from cve_detector.core.security import LoginThrottle
from cve_detector.db.migrate import upgrade_to_head
from cve_detector.db.session import get_sessionmaker
from cve_detector.notifiers import make_notifiers
from cve_detector.notifiers.dispatch import AdminAlerter, Dispatcher
from cve_detector.scanning.scheduler import Scheduler
from cve_detector.sources import make_sources
from cve_detector.web import mount_web_ui, security_headers

# The placeholder in .env.example, refused so that nobody runs with it by mistake.
EXAMPLE_PASSWORD = "change-me"  # noqa: S105


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    password = settings.admin_password.get_secret_value() if settings.admin_password else ""
    if not password:
        raise RuntimeError(
            "CVED_ADMIN_PASSWORD is not set: add it to .env (see .env.example) and restart"
        )
    if password == EXAMPLE_PASSWORD:
        raise RuntimeError("CVED_ADMIN_PASSWORD is still the example value: choose a real one")
    if settings.database_url is None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    upgrade_to_head(settings.sqlalchemy_url)

    app.state.scheduler = None
    if not settings.scheduler_enabled:
        yield
        return
    sources = make_sources(settings)
    notifiers = make_notifiers(settings)
    scheduler = Scheduler(
        get_sessionmaker(),
        sources,
        tick_seconds=settings.scan_tick_seconds,
        retry_after=timedelta(minutes=settings.scan_retry_minutes),
        expiry_warning=timedelta(days=settings.suppression_expiry_warning_days),
        notify=Dispatcher(notifiers),
        after_run=AdminAlerter(notifiers, settings.admin_email) if settings.admin_email else None,
    )
    scheduler.start()
    app.state.scheduler = scheduler
    try:
        yield
    finally:
        scheduler.stop()
        for source in sources:
            source.close()


def _operation_id(route: APIRoute) -> str:
    """Stable OpenAPI operation ids (the function names) for the generated TS client."""
    return route.name


def create_app() -> FastAPI:
    app = FastAPI(
        title="cve_detector",
        version=__version__,
        lifespan=lifespan,
        generate_unique_id_function=_operation_id,
    )
    app.state.login_throttle = LoginThrottle()
    app.middleware("http")(reject_cross_site)
    app.middleware("http")(security_headers)
    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    for router in (
        projects.router,
        findings.router,
        suppressions.router,
        scans.router,
        notifications.router,
        config.router,
    ):
        app.include_router(router, prefix="/api", dependencies=[Depends(require_admin)])
    # Last: its catch-all route must not shadow the API.
    mount_web_ui(app, get_settings().web_dir)
    return app


app = create_app()
