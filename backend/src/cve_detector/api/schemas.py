"""Request and response bodies of the REST API."""

from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from cve_detector.db.enums import (
    AllClearPolicy,
    DependencyScope,
    DependencySource,
    Ecosystem,
    EmailDelivery,
    FindingStatus,
    NotificationKind,
    ScanStatus,
    Severity,
)

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


def _unique_scopes(scopes: list[DependencyScope]) -> list[DependencyScope]:
    return [s for s in DependencyScope if s in scopes]


Scopes = Annotated[list[DependencyScope], AfterValidator(_unique_scopes)]


class _Out(BaseModel):
    """Response body: fields with defaults are always present, so the schema marks them required."""

    model_config = ConfigDict(json_schema_serialization_defaults_required=True)


class Page[T](_Out):
    items: list[T]
    total: int


class _Orm(_Out):
    model_config = ConfigDict(
        from_attributes=True, json_schema_serialization_defaults_required=True
    )


# --- Projects -------------------------------------------------------------------------


class ProjectSettings(BaseModel):
    description: str = Field("", max_length=5000)
    scan_interval_hours: int = Field(24, ge=1, le=24 * 30)
    min_severity: Severity = Severity.LOW
    included_scopes: Scopes = Field(default_factory=lambda: list(DependencyScope))
    notify_minor_updates: bool = False
    all_clear_policy: AllClearPolicy = AllClearPolicy.NEVER
    email_delivery: EmailDelivery = EmailDelivery.SEPARATE


class ProjectCreate(ProjectSettings):
    name: str = Field(min_length=1, max_length=200)


class ProjectUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=5000)
    scan_interval_hours: int | None = Field(None, ge=1, le=24 * 30)
    min_severity: Severity | None = None
    included_scopes: Scopes | None = None
    notify_minor_updates: bool | None = None
    all_clear_policy: AllClearPolicy | None = None
    email_delivery: EmailDelivery | None = None


class SeverityCounts(_Out):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0
    unknown: int = 0


class ProjectOut(_Orm, ProjectCreate):
    id: int
    created_at: datetime
    last_scan_at: datetime | None
    next_scan_at: datetime | None
    last_scan_error: str | None
    last_notified_at: datetime | None
    dependency_count: int = 0
    recipient_count: int = 0
    # Open, not suppressed findings by severity (all scopes, regardless of the threshold).
    open_findings: SeverityCounts = Field(default_factory=SeverityCounts)


# --- Recipients -----------------------------------------------------------------------


class RecipientCreate(BaseModel):
    target: str = Field(max_length=320, pattern=EMAIL_PATTERN)


class RecipientOut(_Orm):
    id: int
    channel: str
    target: str


# --- Dependencies ---------------------------------------------------------------------


class DependencyCreate(BaseModel):
    ecosystem: Ecosystem
    name: str = Field(min_length=1, max_length=400)
    version_spec: str = Field(min_length=1, max_length=200)
    scope: DependencyScope = DependencyScope.RUNTIME
    is_direct: bool | None = True


class DependencyUpdate(BaseModel):
    version_spec: str | None = Field(None, min_length=1, max_length=200)
    scope: DependencyScope | None = None
    is_direct: bool | None = None


class DependencyOut(_Out):
    id: int
    ecosystem: Ecosystem
    name: str
    version_spec: str
    is_exact: bool
    scope: DependencyScope
    is_direct: bool | None
    source: DependencySource
    open_findings: int = 0


# --- Manifests ------------------------------------------------------------------------


class ManifestUpload(BaseModel):
    filename: str = Field(max_length=255)
    content: str = Field(max_length=10_000_000)
    # Needed when the file name does not tell the format (mvn dependency:list output).
    source: DependencySource | None = None


class ManifestApply(ManifestUpload):
    # Versions for entries the file could not resolve, by package name.
    resolved: dict[str, str] = Field(default_factory=dict)
    # Unresolved entries to leave out.
    skip: list[str] = Field(default_factory=list)


class ManifestEntry(_Out):
    name: str
    version_spec: str | None
    scope: DependencyScope
    is_direct: bool | None
    previous_spec: str | None = None
    problem: str | None = None


class ManifestPreview(_Out):
    ecosystem: Ecosystem
    source: DependencySource
    added: list[ManifestEntry]
    changed: list[ManifestEntry]
    removed: list[ManifestEntry]
    unchanged: int
    skipped: list[str]
    unresolved: list[ManifestEntry]
    warnings: list[str]


# --- Suppressions ---------------------------------------------------------------------


class SuppressionCreate(BaseModel):
    advisory_ref: str = Field(min_length=1, max_length=100)
    project_id: int | None = None
    reason: str = Field(min_length=1, max_length=5000)
    expires_at: datetime | None = None


class SuppressionUpdate(BaseModel):
    reason: str | None = Field(None, min_length=1, max_length=5000)
    expires_at: datetime | None = None


class SuppressionOut(_Orm):
    id: int
    advisory_ref: str
    project_id: int | None
    reason: str
    created_at: datetime
    expires_at: datetime | None
    active: bool = True


# --- Findings -------------------------------------------------------------------------


class AdvisoryOut(_Out):
    id: int
    source: str
    source_id: str
    url: str
    aliases: list[str]
    summary: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    published_at: datetime | None
    modified_at: datetime | None
    withdrawn_at: datetime | None
    is_known_exploited: bool


class FindingOut(_Out):
    id: int
    project_id: int
    project_name: str
    dependency: DependencyOut
    advisory: AdvisoryOut
    status: FindingStatus
    fixed_versions: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    suppression: SuppressionOut | None
    notified: bool


# --- History --------------------------------------------------------------------------


class ScanRunOut(_Orm):
    id: int
    started_at: datetime
    finished_at: datetime | None
    status: ScanStatus
    projects_scanned: int
    libraries_queried: int
    findings_new: int
    error: str | None


class NotificationLogOut(_Orm):
    id: int
    project_id: int | None
    kind: NotificationKind
    channel: str
    targets: list[str]
    sent_at: datetime
    success: bool
    error: str | None
