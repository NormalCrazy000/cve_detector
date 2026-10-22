"""Shared library catalog: each ``ecosystem + name`` is stored once and referenced by projects."""

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from cve_detector.db.base import utcnow
from cve_detector.db.enums import DependencyScope, DependencySource, Ecosystem
from cve_detector.db.models import Dependency, Library, Project
from cve_detector.ecosystems import get_handler
from cve_detector.ecosystems.base import InvalidVersionSpecError, ManifestResult, ParsedDependency


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


class DuplicateDependencyError(ValueError):
    """The project already has this library with this version spec."""


def mark_due(project: Project) -> None:
    """Scan the project at the next scheduler tick (changes are batched until then)."""
    now = utcnow()
    if project.next_scan_at is None or project.next_scan_at > now:
        project.next_scan_at = now


def update_dependency(
    session: Session,
    dependency: Dependency,
    *,
    version_spec: str | None = None,
    scope: DependencyScope | None = None,
) -> Dependency:
    """Change the version spec or scope of a dependency in place, keeping its findings.

    Keeping the row (instead of deleting and re-adding it) lets the next scan report
    the findings that a version upgrade resolved. Raises
    :class:`~cve_detector.ecosystems.base.InvalidVersionSpecError` or
    :class:`DuplicateDependencyError`.
    """
    if version_spec is not None:
        spec = get_handler(dependency.library.ecosystem).parse_spec(version_spec)
        if spec.text != dependency.version_spec:
            clash = session.scalars(
                select(Dependency.id).where(
                    Dependency.project_id == dependency.project_id,
                    Dependency.library_id == dependency.library_id,
                    Dependency.version_spec == spec.text,
                )
            ).first()
            if clash is not None:
                raise DuplicateDependencyError(
                    f"{dependency.library.name} {spec.text} is already a dependency"
                )
            dependency.version_spec = spec.text
            dependency.is_exact = spec.is_exact
    if scope is not None:
        dependency.scope = scope
    return dependency


@dataclass(frozen=True, slots=True)
class SyncChange:
    name: str
    version_spec: str
    scope: DependencyScope
    is_direct: bool | None
    # The spec before the change, for ``changed`` entries.
    previous_spec: str | None = None


@dataclass(slots=True)
class SyncPlan:
    """What re-importing a manifest would do to the project's dependencies from that source.

    Dependencies entered by hand or imported from other files are never touched.
    """

    ecosystem: Ecosystem
    source: DependencySource
    added: list[SyncChange] = field(default_factory=list)
    changed: list[SyncChange] = field(default_factory=list)
    removed: list[SyncChange] = field(default_factory=list)
    unchanged: int = 0
    # Entries already present from another source, left as they are.
    skipped: list[str] = field(default_factory=list)
    unresolved: list[ParsedDependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Internal: what to do with existing rows.
    _updates: list[tuple[Dependency, ParsedDependency]] = field(default_factory=list)
    _deletes: list[Dependency] = field(default_factory=list)
    _inserts: list[ParsedDependency] = field(default_factory=list)


def plan_manifest_sync(session: Session, project: Project, result: ManifestResult) -> SyncPlan:
    """Compare a parsed manifest with the project, without changing anything.

    Per library, identical version specs are kept, remaining old and new specs are
    paired as version changes (updated in place), and the rest are added or removed.
    Unresolved entries are reported and left out of the plan.
    """
    handler = get_handler(result.ecosystem)
    plan = SyncPlan(result.ecosystem, result.source, warnings=list(result.warnings))
    wanted: dict[str, list[ParsedDependency]] = {}
    for parsed in result.dependencies:
        if parsed.version_spec is None:
            plan.unresolved.append(parsed)
            continue
        name = handler.normalize_name(parsed.name)
        spec = handler.parse_spec(parsed.version_spec).text
        wanted.setdefault(name, []).append(
            ParsedDependency(name, spec, parsed.is_exact, parsed.scope, parsed.is_direct)
        )

    existing: dict[str, list[Dependency]] = {}
    others: set[tuple[str, str]] = set()
    for row in project.dependencies:
        if row.library.ecosystem is not result.ecosystem:
            continue
        if row.source is result.source:
            existing.setdefault(row.library.name, []).append(row)
        else:
            others.add((row.library.name, row.version_spec))

    for name in sorted(wanted.keys() | existing.keys()):
        new = sorted(wanted.get(name, []), key=lambda d: d.version_spec or "")
        old = sorted(existing.get(name, []), key=lambda d: d.version_spec)
        old_specs = {d.version_spec for d in old}
        new_specs = {d.version_spec for d in new}
        for row in old:
            if row.version_spec in new_specs:
                target = next(n for n in new if n.version_spec == row.version_spec)
                if (row.scope, row.is_direct) == (target.scope, target.is_direct):
                    plan.unchanged += 1
                else:
                    plan._updates.append((row, target))
                    plan.changed.append(_change(target, row.version_spec))
        leftover_old = [d for d in old if d.version_spec not in new_specs]
        leftover_new: list[ParsedDependency] = []
        for parsed in new:
            if parsed.version_spec in old_specs:
                continue
            if (name, parsed.version_spec) in others:
                plan.skipped.append(f"{name} {parsed.version_spec}")
                continue
            leftover_new.append(parsed)
        for old_dep, new_dep in zip(leftover_old, leftover_new, strict=False):
            plan._updates.append((old_dep, new_dep))
            plan.changed.append(_change(new_dep, old_dep.version_spec))
        for old_dep in leftover_old[len(leftover_new) :]:
            plan._deletes.append(old_dep)
            plan.removed.append(
                SyncChange(name, old_dep.version_spec, old_dep.scope, old_dep.is_direct)
            )
        for new_dep in leftover_new[len(leftover_old) :]:
            plan._inserts.append(new_dep)
            plan.added.append(_change(new_dep))
    return plan


def apply_manifest_sync(session: Session, project: Project, plan: SyncPlan) -> None:
    """Apply a plan from :func:`plan_manifest_sync` and schedule a scan."""
    for row in plan._deletes:
        session.delete(row)
    session.flush()
    for row, target in plan._updates:
        row.version_spec = target.version_spec or row.version_spec
        row.is_exact = target.is_exact
        row.scope = target.scope
        row.is_direct = target.is_direct
    session.flush()
    for target in plan._inserts:
        add_dependency(
            session,
            project,
            plan.ecosystem,
            target.name,
            target.version_spec or "",
            scope=target.scope,
            is_direct=target.is_direct,
            source=plan.source,
        )
    mark_due(project)


def _change(dep: ParsedDependency, previous_spec: str | None = None) -> SyncChange:
    return SyncChange(dep.name, dep.version_spec or "", dep.scope, dep.is_direct, previous_spec)
