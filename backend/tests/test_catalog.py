import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.catalog import add_dependency, add_manifest, get_or_create_library
from cve_detector.db.enums import DependencyScope, DependencySource, Ecosystem
from cve_detector.db.models import Dependency, Library, Project
from cve_detector.ecosystems import parse_manifest
from cve_detector.ecosystems.base import InvalidPackageNameError, InvalidVersionSpecError


def test_library_is_created_once(session: Session) -> None:
    first = get_or_create_library(session, Ecosystem.NPM, " left-pad ")
    second = get_or_create_library(session, Ecosystem.NPM, "left-pad")
    other = get_or_create_library(session, Ecosystem.MAVEN, "org.example:left-pad")
    session.commit()

    assert first.id == second.id != other.id
    assert first.name == "left-pad"
    assert first.created_at is not None
    assert len(session.scalars(select(Library)).all()) == 2


def test_invalid_library_name(session: Session) -> None:
    with pytest.raises(InvalidPackageNameError):
        get_or_create_library(session, Ecosystem.MAVEN, "no-group")


def test_dependencies_share_the_catalog(session: Session) -> None:
    one, two = Project(name="demo-project"), Project(name="other-project")
    a = add_dependency(session, one, Ecosystem.NPM, "example-lib", "^1.0.0")
    b = add_dependency(session, two, Ecosystem.NPM, "example-lib", "= v1.2.3")
    session.commit()

    assert a.library_id == b.library_id
    assert (a.version_spec, a.is_exact) == ("^1.0.0", False)
    assert (b.version_spec, b.is_exact) == ("1.2.3", True)


def test_adding_the_same_dependency_updates_it(session: Session) -> None:
    project = Project(name="demo-project")
    first = add_dependency(session, project, Ecosystem.MAVEN, "org.example:lib", "[1.5]")
    second = add_dependency(
        session,
        project,
        Ecosystem.MAVEN,
        "org.example:lib",
        "1.5",
        scope=DependencyScope.DEVELOPMENT,
        is_direct=None,
        source=DependencySource.MVN_DEPENDENCY_LIST,
    )
    session.commit()

    assert first is second
    stored = session.scalars(select(Dependency)).one()
    assert stored.scope is DependencyScope.DEVELOPMENT
    assert stored.is_direct is None
    assert stored.source is DependencySource.MVN_DEPENDENCY_LIST


def test_invalid_version_is_rejected(session: Session) -> None:
    with pytest.raises(InvalidVersionSpecError):
        add_dependency(session, Project(name="demo-project"), Ecosystem.NPM, "lib", "latest")


def test_add_manifest(session: Session) -> None:
    result = parse_manifest(
        DependencySource.PACKAGE_JSON,
        '{"dependencies": {"a": "^1.0.0"}, "devDependencies": {"b": "2.0.0"}}',
    )
    project = Project(name="demo-project")
    saved = add_manifest(session, project, result)
    session.commit()

    assert [(d.library.name, d.scope, d.source) for d in saved] == [
        ("a", DependencyScope.RUNTIME, DependencySource.PACKAGE_JSON),
        ("b", DependencyScope.DEVELOPMENT, DependencySource.PACKAGE_JSON),
    ]


def test_add_manifest_refuses_unresolved_versions(session: Session) -> None:
    result = parse_manifest(
        DependencySource.PACKAGE_JSON, '{"dependencies": {"a": "^1.0.0", "b": "next"}}'
    )
    with pytest.raises(InvalidVersionSpecError, match="unresolved versions: b"):
        add_manifest(session, Project(name="demo-project"), result)
    assert session.scalars(select(Dependency)).all() == []
