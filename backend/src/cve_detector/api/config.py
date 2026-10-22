from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

from cve_detector.api.deps import DbSession
from cve_detector.config_io import ConfigError, export_config, import_config
from cve_detector.db.base import utcnow
from cve_detector.scanning.suppressions import refresh_suppressions

router = APIRouter(prefix="/config", tags=["config"])


class ConfigImport(BaseModel):
    content: str = Field(max_length=10_000_000)


class ImportResult(BaseModel):
    projects_created: int
    projects_updated: int
    recipients_added: int
    dependencies_added: int
    suppressions_added: int
    suppressions_updated: int


@router.get(
    "/export", response_class=Response, responses={200: {"content": {"application/yaml": {}}}}
)
def export_configuration(session: DbSession) -> Response:
    """Projects, recipients, dependencies and suppressions as YAML (no secrets)."""
    filename = f"cve_detector-config-{utcnow():%Y%m%d}.yaml"
    return Response(
        export_config(session),
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/import")
def import_configuration(body: ConfigImport, session: DbSession) -> ImportResult:
    """Merge a YAML configuration: update projects with the same name, add the rest."""
    try:
        summary = import_config(session, body.content)
    except ConfigError as exc:
        session.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    refresh_suppressions(session, utcnow())
    session.commit()
    return ImportResult(**asdict(summary))
