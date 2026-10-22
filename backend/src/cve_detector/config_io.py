"""Export the whole configuration to YAML and merge it back.

Covers projects (settings, recipients, dependencies) and suppressions; never secrets,
findings or history. Importing merges: projects are matched by name and updated,
missing items are added, nothing is deleted.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.api.schemas import EMAIL_PATTERN, ProjectSettings
from cve_detector.catalog import add_dependency, mark_due
from cve_detector.db.enums import DependencyScope, DependencySource, Ecosystem
from cve_detector.db.models import Project, Recipient, Suppression

FORMAT_VERSION = 1


class ConfigError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DependencyEntry(_Strict):
    ecosystem: Ecosystem
    name: str
    version: str
    scope: DependencyScope = DependencyScope.RUNTIME
    direct: bool | None = True
    source: DependencySource = DependencySource.MANUAL


class ProjectEntry(_Strict, ProjectSettings):
    name: str = Field(min_length=1, max_length=200)
    recipients: list[str] = Field(default_factory=list)
    dependencies: list[DependencyEntry] = Field(default_factory=list)


class SuppressionEntry(_Strict):
    advisory: str = Field(min_length=1, max_length=100)
    # Project name; omitted for suppressions that apply to all projects.
    project: str | None = None
    reason: str = Field(min_length=1)
    expires: datetime | None = None


class ConfigFile(_Strict):
    version: int = FORMAT_VERSION
    projects: list[ProjectEntry] = Field(default_factory=list)
    suppressions: list[SuppressionEntry] = Field(default_factory=list)


@dataclass(slots=True)
class ImportSummary:
    projects_created: int = 0
    projects_updated: int = 0
    recipients_added: int = 0
    dependencies_added: int = 0
    suppressions_added: int = 0
    suppressions_updated: int = 0


def export_config(session: Session) -> str:
    projects = session.scalars(select(Project).order_by(Project.name))
    names = {}
    entries = []
    for project in projects:
        names[project.id] = project.name
        entries.append(
            {
                "name": project.name,
                "description": project.description,
                "scan_interval_hours": project.scan_interval_hours,
                "min_severity": project.min_severity.value,
                "included_scopes": list(project.included_scopes),
                "notify_minor_updates": project.notify_minor_updates,
                "all_clear_policy": project.all_clear_policy.value,
                "email_delivery": project.email_delivery.value,
                "recipients": sorted(r.target for r in project.recipients if r.channel == "email"),
                "dependencies": [
                    {
                        "ecosystem": d.library.ecosystem.value,
                        "name": d.library.name,
                        "version": d.version_spec,
                        "scope": d.scope.value,
                        "direct": d.is_direct,
                        "source": d.source.value,
                    }
                    for d in sorted(
                        project.dependencies,
                        key=lambda d: (d.library.ecosystem, d.library.name, d.version_spec),
                    )
                ],
            }
        )
    suppressions = [
        {
            "advisory": s.advisory_ref,
            "project": names.get(s.project_id) if s.project_id else None,
            "reason": s.reason,
            "expires": s.expires_at.isoformat() if s.expires_at else None,
        }
        for s in session.scalars(select(Suppression).order_by(Suppression.id))
    ]
    document: dict[str, Any] = {
        "version": FORMAT_VERSION,
        "projects": entries,
        "suppressions": suppressions,
    }
    header = "# cve_detector configuration (no secrets). Import merges, it never deletes.\n"
    return header + yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def import_config(session: Session, text: str) -> ImportSummary:
    """Merge a YAML configuration. Raises :class:`ConfigError`; nothing is written then.

    The caller commits.
    """
    config = _load(text)
    summary = ImportSummary()
    by_name: dict[str, Project] = {p.name: p for p in session.scalars(select(Project))}
    for entry in config.projects:
        project = by_name.get(entry.name)
        if project is None:
            project = Project(name=entry.name)
            session.add(project)
            by_name[entry.name] = project
            summary.projects_created += 1
        else:
            summary.projects_updated += 1
        settings = entry.model_dump(include=set(ProjectSettings.model_fields))
        settings["included_scopes"] = [s.value for s in entry.included_scopes]
        for key, value in settings.items():
            setattr(project, key, value)

        known = {r.target.lower() for r in project.recipients if r.channel == "email"}
        for target in entry.recipients:
            if target.lower() not in known:
                project.recipients.append(Recipient(channel="email", target=target))
                known.add(target.lower())
                summary.recipients_added += 1

        before = len(project.dependencies)
        for dep in entry.dependencies:
            try:
                add_dependency(
                    session,
                    project,
                    dep.ecosystem,
                    dep.name,
                    dep.version,
                    scope=dep.scope,
                    is_direct=dep.direct,
                    source=dep.source,
                )
            except ValueError as exc:
                raise ConfigError(f"project {entry.name!r}, {dep.name}: {exc}") from exc
        session.flush()
        session.refresh(project, ["dependencies"])
        if (added := len(project.dependencies) - before) > 0:
            summary.dependencies_added += added
            mark_due(project)

    session.flush()
    for item in config.suppressions:
        project_id = None
        if item.project is not None:
            if item.project not in by_name:
                raise ConfigError(
                    f"suppression of {item.advisory}: unknown project {item.project!r}"
                )
            project_id = by_name[item.project].id
        existing = session.scalars(
            select(Suppression).where(
                Suppression.advisory_ref == item.advisory,
                Suppression.project_id.is_(None)
                if project_id is None
                else Suppression.project_id == project_id,
            )
        ).first()
        if existing is None:
            session.add(
                Suppression(
                    advisory_ref=item.advisory,
                    project_id=project_id,
                    reason=item.reason,
                    expires_at=item.expires,
                )
            )
            summary.suppressions_added += 1
        else:
            existing.reason = item.reason
            existing.expires_at = item.expires
            summary.suppressions_updated += 1
    session.flush()
    return summary


def _load(text: str) -> ConfigFile:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("the file must contain a mapping with 'projects' and 'suppressions'")
    try:
        config = ConfigFile.model_validate(data)
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10]
        )
        raise ConfigError(errors) from exc
    if config.version != FORMAT_VERSION:
        raise ConfigError(f"unsupported format version {config.version}")
    for project in config.projects:
        for target in project.recipients:
            if not re.match(EMAIL_PATTERN, target):
                raise ConfigError(f"project {project.name!r}: invalid recipient {target!r}")
    names = [p.name for p in config.projects]
    if len(names) != len(set(names)):
        raise ConfigError("duplicate project names")
    for item in config.suppressions:
        if item.expires is not None and item.expires.tzinfo is None:
            raise ConfigError(f"suppression of {item.advisory}: give the expiry with a timezone")
    return config
