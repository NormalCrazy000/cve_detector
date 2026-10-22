"""FastAPI application entry point: ``uvicorn cve_detector.main:app``."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI

from cve_detector import __version__
from cve_detector.api import health, notifications, scans
from cve_detector.core.config import get_settings
from cve_detector.core.logging import configure_logging
from cve_detector.db.migrate import upgrade_to_head
from cve_detector.db.session import get_sessionmaker
from cve_detector.notifiers import make_notifiers
from cve_detector.notifiers.dispatch import AdminAlerter, Dispatcher
from cve_detector.scanning.scheduler import Scheduler
from cve_detector.sources import make_sources


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
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


def create_app() -> FastAPI:
    app = FastAPI(title="cve_detector", version=__version__, lifespan=lifespan)
    app.include_router(health.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(notifications.router, prefix="/api")
    return app


app = create_app()
