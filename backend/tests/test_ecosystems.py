import pytest

from cve_detector.db.enums import DependencyScope as Scope
from cve_detector.db.enums import DependencySource, Ecosystem
from cve_detector.ecosystems import detect_source, get_handler, parse_manifest
from cve_detector.ecosystems.base import ManifestError, ParsedDependency, merge_duplicates


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("pom.xml", DependencySource.POM_XML),
        ("some/dir/POM.XML", DependencySource.POM_XML),
        ("demo-lib-1.0.pom", DependencySource.POM_XML),
        ("C:\\work\\app\\package.json", DependencySource.PACKAGE_JSON),
        ("package-lock.json", DependencySource.PACKAGE_LOCK),
        ("npm-shrinkwrap.json", DependencySource.PACKAGE_LOCK),
        ("deps.txt", None),
        ("yarn.lock", None),
    ],
)
def test_detect_source(filename: str, source: DependencySource | None) -> None:
    assert detect_source(filename) == source


def test_parse_manifest_dispatches_by_source() -> None:
    result = parse_manifest(DependencySource.PACKAGE_JSON, '{"dependencies": {"a": "1.0.0"}}')
    assert result.ecosystem is Ecosystem.NPM
    assert result.dependencies == [ParsedDependency("a", "1.0.0", is_exact=True)]

    result = parse_manifest(DependencySource.MVN_DEPENDENCY_LIST, "g:a:jar:1.0:compile")
    assert result.ecosystem is Ecosystem.MAVEN


def test_parse_manifest_rejects_manual_source() -> None:
    with pytest.raises(ManifestError):
        parse_manifest(DependencySource.MANUAL, "")


def test_every_ecosystem_has_a_handler() -> None:
    for ecosystem in Ecosystem:
        assert get_handler(ecosystem).ecosystem is ecosystem


def test_merge_duplicates() -> None:
    def dep(scope: Scope, is_direct: bool | None) -> ParsedDependency:
        return ParsedDependency("lib", "1.0.0", True, scope=scope, is_direct=is_direct)

    merged = merge_duplicates(
        [dep(Scope.DEVELOPMENT, True), dep(Scope.OPTIONAL, False), dep(Scope.PROVIDED, False)]
    )
    assert merged == [dep(Scope.PROVIDED, True)]

    assert merge_duplicates([dep(Scope.RUNTIME, None), dep(Scope.RUNTIME, None)]) == [
        dep(Scope.RUNTIME, None)
    ]
    assert merge_duplicates([dep(Scope.RUNTIME, None), dep(Scope.RUNTIME, True)]) == [
        dep(Scope.RUNTIME, True)
    ]
