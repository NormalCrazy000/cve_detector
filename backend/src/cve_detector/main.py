"""FastAPI application entry point: ``uvicorn cve_detector.main:app``."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from cve_detector import __version__
from cve_detector.api import health
from cve_detector.core.config import get_settings
from cve_detector.core.logging import configure_logging
from cve_detector.db.migrate import upgrade_to_head


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    if settings.database_url is None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    upgrade_to_head(settings.sqlalchemy_url)
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="cve_detector", version=__version__, lifespan=lifespan)
    app.include_router(health.router, prefix="/api")
    return app


app = create_app()
