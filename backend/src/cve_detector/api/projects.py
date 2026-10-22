"""Projects and what belongs to them: recipients, dependencies, manifest imports."""

from collections import defaultdict
from dataclasses import replace
from typing import Any

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cve_detector.api.deps import DbSession
from cve_detector.api.schemas import (
    DependencyCreate,
    DependencyOut,
    DependencyUpdate,
    ManifestApply,
    ManifestEntry,
    ManifestPreview,
    ManifestUpload,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    RecipientCreate,
    RecipientOut,
    SeverityCounts,
)
from cve_detector.catalog import (
    DuplicateDependencyError,
    SyncChange,
    SyncPlan,
    add_dependency,
    apply_manifest_sync,
    mark_due,
    plan_manifest_sync,
    update_dependency,
)
from cve_detector.db.enums import FindingStatus
from cve_detector.db.models import Advisory, Dependency, Finding, Project, Recipient
from cve_detector.ecosystems import detect_source, get_handler, parse_manifest
from cve_detector.ecosystems.base import (
    InvalidPackageNameError,
    InvalidVersionSpecError,
    ManifestError,
    ManifestResult,
    ParsedDependency,
)

router = APIRouter(prefix="/projects", tags=["projects"])

_OPEN = (FindingStatus.AFFECTED, FindingStatus.POTENTIALLY_AFFECTED)


# --- Projects -------------------------------------------------------------------------


@router.get("")
def list_projects(session: DbSession) -> list[ProjectOut]:
    projects = list(session.scalars(select(Project).order_by(Project.name)))
    return _project_out(session, projects)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_project(body: ProjectCreate, session: DbSession) -> ProjectOut:
    _ensure_unique_name(session, body.name)
    project = Project(**_project_fields(body.model_dump()))
    session.add(project)
    session.commit()
    return _project_out(session, [project])[0]


@router.get("/{project_id}")
def get_project(project_id: int, session: DbSession) -> ProjectOut:
    return _project_out(session, [_get_project(session, project_id)])[0]


@router.patch("/{project_id}")
def update_project(project_id: int, body: ProjectUpdate, session: DbSession) -> ProjectOut:
    project = _get_project(session, project_id)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("name") not in (None, project.name):
        _ensure_unique_name(session, changes["name"])
    for key, value in _project_fields(changes).items():
        if value is not None:
            setattr(project, key, value)
    session.commit()
    return _project_out(session, [project])[0]


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: int, session: DbSession) -> None:
    session.delete(_get_project(session, project_id))
    session.commit()


# --- Recipients -----------------------------------------------------------------------


@router.get("/{project_id}/recipients")
def list_recipients(project_id: int, session: DbSession) -> list[RecipientOut]:
    project = _get_project(session, project_id)
    return [RecipientOut.model_validate(r) for r in project.recipients]


@router.post("/{project_id}/recipients", status_code=status.HTTP_201_CREATED)
def add_recipient(project_id: int, body: RecipientCreate, session: DbSession) -> RecipientOut:
    project = _get_project(session, project_id)
    target = body.target.strip()
    if any(r.channel == "email" and r.target.lower() == target.lower() for r in project.recipients):
        raise HTTPException(status.HTTP_409_CONFLICT, "recipient already present")
    recipient = Recipient(channel="email", target=target)
    project.recipients.append(recipient)
    session.commit()
    return RecipientOut.model_validate(recipient)


@router.delete("/{project_id}/recipients/{recipient_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_recipient(project_id: int, recipient_id: int, session: DbSession) -> None:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "recipient not found")
    session.delete(recipient)
    session.commit()


# --- Dependencies ---------------------------------------------------------------------


@router.get("/{project_id}/dependencies")
def list_dependencies(project_id: int, session: DbSession) -> list[DependencyOut]:
    project = _get_project(session, project_id)
    dependencies = sorted(
        project.dependencies, key=lambda d: (d.library.ecosystem, d.library.name, d.version_spec)
    )
    return _dependency_out(session, dependencies)


@router.post("/{project_id}/dependencies", status_code=status.HTTP_201_CREATED)
def create_dependency(project_id: int, body: DependencyCreate, session: DbSession) -> DependencyOut:
    project = _get_project(session, project_id)
    try:
        dependency = add_dependency(
            session,
            project,
            body.ecosystem,
            body.name,
            body.version_spec,
            scope=body.scope,
            is_direct=body.is_direct,
        )
    except (InvalidPackageNameError, InvalidVersionSpecError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    mark_due(project)
    session.commit()
    return _dependency_out(session, [dependency])[0]


@router.patch("/{project_id}/dependencies/{dependency_id}")
def edit_dependency(
    project_id: int, dependency_id: int, body: DependencyUpdate, session: DbSession
) -> DependencyOut:
    dependency = _get_dependency(session, project_id, dependency_id)
    try:
        update_dependency(session, dependency, version_spec=body.version_spec, scope=body.scope)
    except InvalidVersionSpecError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except DuplicateDependencyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if "is_direct" in body.model_fields_set:
        dependency.is_direct = body.is_direct
    mark_due(dependency.project)
    session.commit()
    return _dependency_out(session, [dependency])[0]


@router.delete("/{project_id}/dependencies/{dependency_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dependency(project_id: int, dependency_id: int, session: DbSession) -> None:
    session.delete(_get_dependency(session, project_id, dependency_id))
    session.commit()


# --- Manifests ------------------------------------------------------------------------


@router.post("/{project_id}/manifest/preview")
def preview_manifest(project_id: int, body: ManifestUpload, session: DbSession) -> ManifestPreview:
    """What importing the file would change; nothing is saved."""
    project = _get_project(session, project_id)
    result = _parse(body)
    return _preview(_plan(session, project, result))


@router.post("/{project_id}/manifest/apply")
def apply_manifest(project_id: int, body: ManifestApply, session: DbSession) -> ManifestPreview:
    """Synchronize the project with the file: dependencies previously imported from the
    same kind of file are added, updated or removed; others are left alone."""
    project = _get_project(session, project_id)
    result = _complete(_parse(body), body.resolved, set(body.skip))
    plan = _plan(session, project, result)
    if plan.unresolved:
        names = ", ".join(d.name for d in plan.unresolved)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"versions missing for: {names}")
    apply_manifest_sync(session, project, plan)
    session.commit()
    return _preview(plan)


# --- Helpers --------------------------------------------------------------------------


def _get_project(session: Session, project_id: int) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return project


def _get_dependency(session: Session, project_id: int, dependency_id: int) -> Dependency:
    dependency = session.get(Dependency, dependency_id)
    if dependency is None or dependency.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dependency not found")
    return dependency


def _ensure_unique_name(session: Session, name: str) -> None:
    if session.scalars(select(Project.id).where(Project.name == name)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"a project named {name!r} already exists")


def _project_fields(data: dict[str, Any]) -> dict[str, Any]:
    if data.get("included_scopes") is not None:
        data["included_scopes"] = [s.value for s in data["included_scopes"]]
    return data


def _project_out(session: Session, projects: list[Project]) -> list[ProjectOut]:
    ids = [p.id for p in projects]
    counts: dict[int, dict[str, int]] = defaultdict(dict)
    rows = session.execute(
        select(Dependency.project_id, Advisory.severity, func.count())
        .join(Finding.dependency)
        .join(Finding.advisory)
        .where(
            Dependency.project_id.in_(ids),
            Finding.status.in_(_OPEN),
            Finding.suppression_id.is_(None),
        )
        .group_by(Dependency.project_id, Advisory.severity)
    )
    for project_id, severity, count in rows:
        counts[project_id][severity.value] = count
    return [
        ProjectOut.model_validate(project).model_copy(
            update={
                "dependency_count": len(project.dependencies),
                "recipient_count": len(project.recipients),
                "open_findings": SeverityCounts(**counts[project.id]),
            }
        )
        for project in projects
    ]


def _dependency_out(session: Session, dependencies: list[Dependency]) -> list[DependencyOut]:
    ids = [d.id for d in dependencies]
    rows = session.execute(
        select(Finding.dependency_id, func.count())
        .where(
            Finding.dependency_id.in_(ids),
            Finding.status.in_(_OPEN),
            Finding.suppression_id.is_(None),
        )
        .group_by(Finding.dependency_id)
    )
    open_counts: dict[int, int] = {dependency_id: count for dependency_id, count in rows}
    return [dependency_out(d, open_counts.get(d.id, 0)) for d in dependencies]


def dependency_out(dependency: Dependency, open_findings: int = 0) -> DependencyOut:
    return DependencyOut(
        id=dependency.id,
        ecosystem=dependency.library.ecosystem,
        name=dependency.library.name,
        version_spec=dependency.version_spec,
        is_exact=dependency.is_exact,
        scope=dependency.scope,
        is_direct=dependency.is_direct,
        source=dependency.source,
        open_findings=open_findings,
    )


def _parse(body: ManifestUpload) -> ManifestResult:
    source = body.source or detect_source(body.filename)
    if source is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"cannot tell the format of {body.filename!r}: choose it explicitly",
        )
    try:
        return parse_manifest(source, body.content)
    except ManifestError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _complete(result: ManifestResult, resolved: dict[str, str], skip: set[str]) -> ManifestResult:
    """Fill in the versions the user provided for unresolved entries, drop skipped ones."""
    handler = get_handler(result.ecosystem)
    completed: list[ParsedDependency] = []
    for dep in result.dependencies:
        if dep.version_spec is None and dep.name in skip:
            continue
        if dep.version_spec is None and dep.name in resolved:
            try:
                spec = handler.parse_spec(resolved[dep.name])
            except InvalidVersionSpecError as exc:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, f"{dep.name}: {exc}"
                ) from exc
            dep = replace(dep, version_spec=spec.text, is_exact=spec.is_exact, problem=None)
        completed.append(dep)
    return replace(result, dependencies=completed)


def _plan(session: Session, project: Project, result: ManifestResult) -> SyncPlan:
    try:
        return plan_manifest_sync(session, project, result)
    except (InvalidPackageNameError, InvalidVersionSpecError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _preview(plan: SyncPlan) -> ManifestPreview:
    def entry(change: SyncChange) -> ManifestEntry:
        return ManifestEntry(
            name=change.name,
            version_spec=change.version_spec,
            scope=change.scope,
            is_direct=change.is_direct,
            previous_spec=change.previous_spec,
        )

    return ManifestPreview(
        ecosystem=plan.ecosystem,
        source=plan.source,
        added=[entry(c) for c in plan.added],
        changed=[entry(c) for c in plan.changed],
        removed=[entry(c) for c in plan.removed],
        unchanged=plan.unchanged,
        skipped=plan.skipped,
        unresolved=[
            ManifestEntry(
                name=d.name,
                version_spec=None,
                scope=d.scope,
                is_direct=d.is_direct,
                problem=d.problem,
            )
            for d in plan.unresolved
        ],
        warnings=plan.warnings,
    )
