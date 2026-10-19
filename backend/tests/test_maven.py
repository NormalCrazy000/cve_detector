from pathlib import Path

import pytest

from cve_detector.db.enums import DependencyScope as Scope
from cve_detector.ecosystems.base import (
    InvalidPackageNameError,
    InvalidVersionSpecError,
    ManifestError,
    ParsedDependency,
)
from cve_detector.ecosystems.maven import MavenHandler

FIXTURES = Path(__file__).parent / "fixtures"
maven = MavenHandler()


def test_valid_name() -> None:
    assert maven.normalize_name(" org.example:demo-lib ") == "org.example:demo-lib"


@pytest.mark.parametrize("name", ["", "demo-lib", "a:b:c", "org.example:", "${g}:a", "a b:c"])
def test_invalid_names(name: str) -> None:
    with pytest.raises(InvalidPackageNameError):
        maven.normalize_name(name)


@pytest.mark.parametrize(
    ("text", "canonical", "is_exact"),
    [
        ("3.12.0", "3.12.0", True),
        ("1.0-SNAPSHOT", "1.0-SNAPSHOT", True),
        ("[1.5]", "1.5", True),
        ("[1.0, 2.0)", "[1.0,2.0)", False),
        ("(,1.0],[1.2,)", "(,1.0],[1.2,)", False),
        ("[1.0,)", "[1.0,)", False),
    ],
)
def test_parse_spec(text: str, canonical: str, is_exact: bool) -> None:
    spec = maven.parse_spec(text)
    assert (spec.text, spec.is_exact) == (canonical, is_exact)


@pytest.mark.parametrize(
    "text",
    ["", "${lib.version}", "[1.0", "[1.0,2.0", "[,]", "(1.0)", "[2.0,1.0)", "1.0]", "(1.0,1.0)"],
)
def test_invalid_specs(text: str) -> None:
    with pytest.raises(InvalidVersionSpecError):
        maven.parse_spec(text)


@pytest.mark.parametrize(
    ("spec", "inside", "outside"),
    [
        ("3.12.0", ["3.12.0"], ["3.12.1"]),
        ("[1.0,2.0)", ["1.0", "1.9.9"], ["0.9", "2.0"]),
        ("(,1.0],[1.2,)", ["0.5", "1.0", "1.2", "5.0"], ["1.1"]),
        ("[1.5]", ["1.5"], ["1.5.1"]),
    ],
)
def test_range_containment(spec: str, inside: list[str], outside: list[str]) -> None:
    intervals = maven.spec_intervals(maven.parse_spec(spec))

    def allowed(version: str) -> bool:
        return any(i.contains(maven.parse_version(version)) for i in intervals)

    for version in inside:
        assert allowed(version), version
    for version in outside:
        assert not allowed(version), version


def test_pom() -> None:
    result = maven.parse_pom((FIXTURES / "pom.xml").read_text())

    assert result.dependencies == [
        ParsedDependency(
            "org.example:bom-lib",
            None,
            False,
            problem="version not declared, probably managed by "
            "the parent POM or an imported BOM (org.example:demo-bom)",
        ),
        # Version and scope come from <dependencyManagement>.
        ParsedDependency("org.example:managed-lib", "1.4.2", True, scope=Scope.PROVIDED),
        ParsedDependency(
            "org.example:parent-prop-lib",
            None,
            False,
            problem="property ${defined.in.parent} is not defined in this POM",
        ),
        ParsedDependency("org.example:pinned-lib", "1.5", True, scope=Scope.OPTIONAL),
        # Also declared with a test classifier: the runtime scope wins.
        ParsedDependency("org.example:plain-lib", "3.12.0", True),
        # Nested properties: ${lib.range} -> [1.0,${lib.major}) -> [1.0,2.0)
        ParsedDependency("org.example:range-lib", "[1.0,2.0)", False),
        # groupId and version inherited from <parent>.
        ParsedDependency("org.example:sibling-lib", "2.1.0", True),
        # test scope wins over <optional>.
        ParsedDependency("org.example:test-lib", "5.10.0", True, scope=Scope.DEVELOPMENT),
    ]
    assert len(result.warnings) == 2
    assert result.warnings[0].startswith("dependency ${undefined.group}:broken")
    assert "<profiles>" in result.warnings[1]


def test_pom_without_namespace_and_with_modules() -> None:
    result = maven.parse_pom(
        """<project>
             <groupId>org.example</groupId><artifactId>root</artifactId><version>1</version>
             <modules><module>core</module></modules>
             <dependencies>
               <dependency><groupId>org.example</groupId><artifactId>lib</artifactId>
                 <version>2.0</version><scope>system</scope></dependency>
             </dependencies>
           </project>"""
    )
    assert result.dependencies == [
        ParsedDependency("org.example:lib", "2.0", True, scope=Scope.PROVIDED)
    ]
    assert result.warnings == [
        "this is a multi-module POM: import each module's pom.xml "
        "or the mvn dependency:list output of the whole build"
    ]


def test_pom_cyclic_properties_do_not_hang() -> None:
    result = maven.parse_pom(
        """<project><properties><a>${b}</a><b>${a}</b></properties>
             <dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>
               <version>${a}</version></dependency></dependencies></project>"""
    )
    assert result.dependencies[0].version_spec is None


@pytest.mark.parametrize(
    "content",
    [
        "not xml",
        "<notaproject/>",
        # External entities (XXE) and entity expansion (billion laughs) are refused.
        '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<project>&x;</project>",
        '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        "<project>&b;</project>",
    ],
)
def test_pom_rejects_invalid_or_unsafe_xml(content: str) -> None:
    with pytest.raises(ManifestError):
        maven.parse_pom(content)


def test_dependency_list() -> None:
    result = maven.parse_dependency_list((FIXTURES / "mvn-dependency-list.txt").read_text())

    def dep(name: str, version: str, scope: Scope = Scope.RUNTIME) -> ParsedDependency:
        return ParsedDependency(f"org.example:{name}", version, True, scope=scope, is_direct=None)

    assert result.dependencies == [
        dep("colored-lib", "0.9"),
        dep("file-output-lib", "1.0.0"),
        dep("optional-lib", "1.1", Scope.OPTIONAL),
        dep("plain-lib", "3.12.0"),
        dep("servlet-api", "4.0.1", Scope.PROVIDED),
        dep("transitive-lib", "2.0.1"),
    ]
    assert result.warnings == []


def test_dependency_list_without_dependencies() -> None:
    result = maven.parse_dependency_list("[INFO] BUILD SUCCESS\n")
    assert result.dependencies == []
    assert result.warnings == ["no dependencies found; expected the output of mvn dependency:list"]


def test_pom_with_invalid_version_asks_the_user() -> None:
    result = maven.parse_pom(
        """<project><dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>
             <version>[1.0</version></dependency></dependencies></project>"""
    )
    assert result.dependencies[0].problem == "invalid Maven version range: '[1.0'"


def test_dependency_list_skips_unknown_scopes() -> None:
    result = maven.parse_dependency_list("g:bom:pom:1.0:import\n")
    assert result.dependencies == []
