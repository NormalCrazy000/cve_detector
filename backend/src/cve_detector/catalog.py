"""Shared library catalog: each ``ecosystem + name`` is stored once and referenced by projects."""

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from cve_detector.db.enums import DependencyScope, DependencySource, Ecosystem
from cve_detector.db.models import Dependency, Library, Project
from cve_detector.ecosystems import get_handler
from cve_detector.ecosystems.base import InvalidVersionSpecError, ManifestResult


def get_or_create_library(session: Session, ecosystem: Ecosystem, name: str) -> Library:
    """Return the catalog entry for a package, creating it if needed.

    Raises :class:`~cve_detector.ecosystems.base.InvalidPackageNameError`.
    """
    name = get_handler(ecosystem).normalize_name(name)
    # INSERT .. ON CONFLICT DO NOTHING is safe against concurrent sessions creating
    # the same library (API and scheduler run in different threads).
    session.execute(
        insert(Library)
        .values(ecosystem=ecosystem, name=name)
        .on_conflict_do_nothing(index_elements=["ecosystem", "name"])
    )
    return session.scalars(
        select(Library).where(Library.ecosystem == ecosystem, Library.name == name)
    ).one()


def add_dependency(
    session: Session,
    project: Project,
    ecosystem: Ecosystem,
    name: str,
    version_spec: str,
    *,
    scope: DependencyScope = DependencyScope.RUNTIME,
    is_direct: bool | None = True,
    source: DependencySource = DependencySource.MANUAL,
) -> Dependency:
    """Add a dependency to a project, or update the existing one with the same version spec.

    The spec is validated and stored in canonical form. Raises
    :class:`~cve_detector.ecosystems.base.InvalidPackageNameError` or
    :class:`~cve_detector.ecosystems.base.InvalidVersionSpecError`.
    """
    spec = get_handler(ecosystem).parse_spec(version_spec)
    library = get_or_create_library(session, ecosystem, name)
    if project.id is None:
        session.add(project)
        session.flush()
    dependency = session.scalars(
        select(Dependency).where(
            Dependency.project_id == project.id,
            Dependency.library_id == library.id,
            Dependency.version_spec == spec.text,
        )
    ).one_or_none()
    if dependency is None:
        dependency = Dependency(
            project=project, library=library, version_spec=spec.text, is_exact=spec.is_exact
        )
        session.add(dependency)
    dependency.scope = scope
    dependency.is_direct = is_direct
    dependency.source = source
    return dependency


def add_manifest(session: Session, project: Project, result: ManifestResult) -> list[Dependency]:
    """Save every dependency of a parsed manifest.

    Unresolved entries must be completed or removed first; otherwise
    :class:`~cve_detector.ecosystems.base.InvalidVersionSpecError` is raised before
    anything is written.
    """
    unresolved = [d.name for d in result.dependencies if d.version_spec is None]
    if unresolved:
        raise InvalidVersionSpecError(f"unresolved versions: {', '.join(unresolved)}")
    return [
        add_dependency(
            session,
            project,
            result.ecosystem,
            dep.name,
            dep.version_spec or "",
            scope=dep.scope,
            is_direct=dep.is_direct,
            source=result.source,
        )
        for dep in result.dependencies
    ]
