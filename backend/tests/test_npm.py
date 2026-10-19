import json
from pathlib import Path

import pytest

from cve_detector.db.enums import DependencyScope as Scope
from cve_detector.ecosystems.base import (
    InvalidPackageNameError,
    InvalidVersionSpecError,
    ManifestError,
    ParsedDependency,
)
from cve_detector.ecosystems.npm import NpmHandler

FIXTURES = Path(__file__).parent / "fixtures"
npm = NpmHandler()


@pytest.mark.parametrize("name", ["lodash", "@types/node", "JSONStream", "a.b-c_d~e"])
def test_valid_names(name: str) -> None:
    assert npm.normalize_name(f"  {name} ") == name


@pytest.mark.parametrize("name", ["", "Bad Name", "../evil", "@scope", ".hidden", "a" * 215])
def test_invalid_names(name: str) -> None:
    with pytest.raises(InvalidPackageNameError):
        npm.normalize_name(name)


@pytest.mark.parametrize(
    ("text", "canonical", "is_exact"),
    [
        ("4.17.21", "4.17.21", True),
        ("=v1.2.3", "1.2.3", True),
        ("1.2.3-beta.1+build.5", "1.2.3-beta.1+build.5", True),
        ("^4.2.0", "^4.2.0", False),
        ("1.2", "1.2", False),
        (">= 1.2.3   < 2", ">=1.2.3 <2", False),
        ("", "*", False),
        ("1.2.3 - 2.3.4", "1.2.3 - 2.3.4", False),
    ],
)
def test_parse_spec(text: str, canonical: str, is_exact: bool) -> None:
    spec = npm.parse_spec(text)
    assert (spec.text, spec.is_exact) == (canonical, is_exact)


@pytest.mark.parametrize(
    "text", ["latest", ">>1", "1.2.3.4", "^a", "1 - 2", "<=>1", ">2.0.0 <1.0.0"]
)
def test_invalid_specs(text: str) -> None:
    with pytest.raises(InvalidVersionSpecError):
        npm.parse_spec(text)


@pytest.mark.parametrize("text", ["1.2", "latest", "^1.0.0"])
def test_parse_version_requires_a_full_version(text: str) -> None:
    with pytest.raises(InvalidVersionSpecError):
        npm.parse_version(text)


@pytest.mark.parametrize(
    ("spec", "inside", "outside"),
    [
        ("1.2.3", ["1.2.3"], ["1.2.4"]),
        ("^4.2.0", ["4.2.0", "4.9.9"], ["4.1.9", "5.0.0"]),
        ("^0.2.3", ["0.2.9"], ["0.3.0"]),
        ("~1.2.3", ["1.2.9"], ["1.3.0"]),
        ("~>1.2", ["1.2.9"], ["1.3.0"]),
        ("1.2", ["1.2.0", "1.2.9"], ["1.3.0"]),
        ("1", ["1.9.9"], ["2.0.0"]),
        ("1.*", ["1.5.0"], ["2.0.0"]),
        ("1.2.x", ["1.2.5"], ["1.3.0"]),
        ("^0.x", ["0.9.0"], ["1.0.0"]),
        ("^1.x", ["1.9.0"], ["2.0.0", "0.9.0"]),
        (">1.2", ["1.3.0"], ["1.2.9"]),
        ("<=1.2", ["1.2.9"], ["1.3.0"]),
        (">=16", ["16.0.0", "20.1.0"], ["15.9.9"]),
        ("*", ["0.0.1", "99.0.0"], []),
        ("x", ["1.0.0"], []),
        ("1.2.3 - 2.3.4", ["2.3.4"], ["2.3.5"]),
        ("<1.0.0 || >=2.0.0", ["0.5.0", "2.1.0"], ["1.5.0"]),
        ("1 || >=3.1 <4", ["1.5.0", "3.5.0"], ["2.0.0", "3.0.0", "4.0.0"]),
    ],
)
def test_range_containment(spec: str, inside: list[str], outside: list[str]) -> None:
    intervals = npm.spec_intervals(npm.parse_spec(spec))

    def allowed(version: str) -> bool:
        return any(i.contains(npm.parse_version(version)) for i in intervals)

    for version in inside:
        assert allowed(version), version
    for version in outside:
        assert not allowed(version), version


def test_package_json() -> None:
    result = npm.parse_package_json((FIXTURES / "package.json").read_text())

    assert result.dependencies == [
        ParsedDependency("@example/real-name", "^3.1.0", is_exact=False),  # npm: alias
        ParsedDependency("@example/scoped", "~2.0.1", is_exact=False),
        ParsedDependency(
            "bad-version",
            None,
            False,
            problem="unsupported version '>>1', enter a version or range",
        ),
        ParsedDependency("caret-lib", "^4.2.0", is_exact=False),
        ParsedDependency("dev-lib", "^9.0.0", is_exact=False, scope=Scope.DEVELOPMENT),
        ParsedDependency("exact-lib", "4.17.21", is_exact=True),
        ParsedDependency("optional-lib", "2.x", is_exact=False, scope=Scope.OPTIONAL),
        ParsedDependency("optional-peer", "*", is_exact=False, scope=Scope.OPTIONAL),
        ParsedDependency("partial-lib", "1.2", is_exact=False),
        ParsedDependency("peer-lib", ">=16", is_exact=False, scope=Scope.PROVIDED),
        # Listed in both dependencies and devDependencies: the runtime scope wins.
        ParsedDependency("shared-lib", "1.0.0", is_exact=True),
        ParsedDependency(
            "tagged", None, False, problem="dist-tag 'latest' is not a version, enter one"
        ),
    ]
    skipped = [w.split(":")[0] for w in result.warnings]
    assert skipped == [
        "dependencies.from-git",
        "dependencies.from-github",
        "dependencies.from-file",
        "dependencies.not-a-string",
        "dependencies.Bad Name",
    ]


def test_package_json_alias_without_version() -> None:
    result = npm.parse_package_json(json.dumps({"dependencies": {"x": "npm:@example/real"}}))
    assert result.dependencies == [ParsedDependency("@example/real", "*", is_exact=False)]


def test_package_lock() -> None:
    result = npm.parse_package_lock((FIXTURES / "package-lock.json").read_text())

    def dep(
        name: str, version: str, scope: Scope = Scope.RUNTIME, *, direct: bool
    ) -> ParsedDependency:
        return ParsedDependency(name, version, is_exact=True, scope=scope, is_direct=direct)

    assert result.dependencies == [
        dep("@example/real-name", "3.1.4", direct=True),  # aliased as "aliased"
        dep("@example/scoped", "0.0.1", direct=False),
        dep("dev-helper", "1.0.0", Scope.DEVELOPMENT, direct=False),
        dep("dev-lib", "9.1.0", Scope.DEVELOPMENT, direct=True),
        dep("dev-opt-lib", "1.0.0", Scope.DEVELOPMENT, direct=False),
        dep("direct-lib", "1.4.0", direct=True),
        dep("member-dep", "2.0.0", direct=True),  # declared by a workspace package
        dep("nested-lib", "2.5.0", direct=False),
        # Also present as a dev dependency of the workspace: the runtime scope wins.
        dep("nested-lib", "3.0.0", direct=False),
        dep("opt-lib", "1.0.0", Scope.OPTIONAL, direct=False),
        dep("peer-lib", "18.0.0", Scope.PROVIDED, direct=False),
    ]
    assert [w.split(":")[0] for w in result.warnings] == [
        "node_modules/git-lib",
        "node_modules/no-version",
    ]


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        json.dumps({"lockfileVersion": 1, "dependencies": {}}),
        json.dumps({"lockfileVersion": 3}),
    ],
)
def test_package_lock_rejects_unsupported_files(content: str) -> None:
    with pytest.raises(ManifestError):
        npm.parse_package_lock(content)


def test_package_lock_skips_invalid_entries() -> None:
    lock = {
        "lockfileVersion": 2,
        "packages": {"node_modules/bad": {"version": "not-a-version"}},
    }
    result = npm.parse_package_lock(json.dumps(lock))
    assert result.dependencies == []
    assert result.warnings == [
        "node_modules/bad: invalid npm version range: 'not-a-version', skipped"
    ]
