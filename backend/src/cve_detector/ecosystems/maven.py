"""Maven: ``groupId:artifactId`` names, version ranges, ``pom.xml`` and ``mvn dependency:list``.

Limits of ``pom.xml`` import: only the file itself is read. Parent POMs, imported BOMs
and transitive dependencies are not resolved; versions that come from them are reported
as unresolved. ``mvn dependency:list`` output covers those cases.
"""

import re
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring
from univers.version_range import MavenVersionRange, VersionRange
from univers.versions import MavenVersion, Version

from cve_detector.db.enums import DependencyScope, DependencySource, Ecosystem
from cve_detector.ecosystems.base import (
    EcosystemHandler,
    InvalidPackageNameError,
    InvalidVersionSpecError,
    ManifestError,
    ManifestParser,
    ManifestResult,
    ParsedDependency,
    VersionSpec,
    merge_duplicates,
)

_ID = r"[A-Za-z0-9_.-]+"
_NAME_RE = re.compile(rf"^{_ID}:{_ID}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
_RANGE_RE = re.compile(r"^[\[(][^\[\]()]*[\])](?:,[\[(][^\[\]()]*[\])])*$")
_RESTRICTION_RE = re.compile(r"[\[(]([^\[\]()]*)[\])]")
_BOUND_RE = re.compile(r"[^\[\](),]+")
_PROPERTY_RE = re.compile(r"\$\{([^}]+)\}")
_MAX_PROPERTY_DEPTH = 10

_SCOPES = {
    "compile": DependencyScope.RUNTIME,
    "runtime": DependencyScope.RUNTIME,
    "provided": DependencyScope.PROVIDED,
    "system": DependencyScope.PROVIDED,
    "test": DependencyScope.DEVELOPMENT,
}

# "[INFO]    org.example:demo-lib:jar:1.2.3:compile -- module demo.lib (optional)"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_LIST_LINE_RE = re.compile(rf"^(?:\[\w+\])?\s*({_ID}(?::{_ID}){{4,5}})(?:\s+.*)?$")


class MavenHandler(EcosystemHandler):
    ecosystem = Ecosystem.MAVEN

    def normalize_name(self, name: str) -> str:
        name = name.strip()
        if not _NAME_RE.match(name):
            raise InvalidPackageNameError(
                f"invalid Maven coordinates {name!r}, expected groupId:artifactId"
            )
        return name

    def parse_version(self, text: str) -> Version:
        text = text.strip()
        if not _VERSION_RE.match(text):
            raise InvalidVersionSpecError(f"invalid Maven version: {text!r}")
        return MavenVersion(text)

    def parse_spec(self, text: str) -> VersionSpec:
        text = "".join(text.split())
        if not text.startswith(("[", "(")):
            # A plain version is a "soft requirement": the version Maven actually uses.
            self.parse_version(text)
            return VersionSpec(text, is_exact=True)
        if not _RANGE_RE.match(text) or not all(
            _VERSION_RE.match(bound) for bound in _BOUND_RE.findall(text)
        ):
            raise InvalidVersionSpecError(f"invalid Maven version range: {text!r}")
        if any(r.strip(",") == "" for r in _RESTRICTION_RE.findall(text)):
            raise InvalidVersionSpecError(f"Maven version range without bounds: {text!r}")
        if text.startswith("[") and text.endswith("]") and "," not in text:
            pinned = text[1:-1]
            self.parse_version(pinned)
            return VersionSpec(pinned, is_exact=True)
        spec = VersionSpec(text, is_exact=False)
        self.parse_range(spec)
        return spec

    def parse_range(self, spec: VersionSpec) -> VersionRange:
        native = f"[{spec.text}]" if spec.is_exact else spec.text
        try:
            version_range: VersionRange = MavenVersionRange.from_native(native)  # type: ignore[no-untyped-call]
        except Exception as exc:
            raise InvalidVersionSpecError(f"invalid Maven version range: {spec.text!r}") from exc
        return version_range

    def manifest_parsers(self) -> dict[DependencySource, ManifestParser]:
        return {
            DependencySource.POM_XML: self.parse_pom,
            DependencySource.MVN_DEPENDENCY_LIST: self.parse_dependency_list,
        }

    def parse_pom(self, content: str) -> ManifestResult:
        project = _parse_xml(content)
        result = ManifestResult(Ecosystem.MAVEN, DependencySource.POM_XML)
        properties = _properties(project)
        resolve = _PropertyResolver(properties)

        managed: dict[str, tuple[str | None, str | None]] = {}
        boms: list[str] = []
        for dep in _children(project, "dependencyManagement", "dependencies", "dependency"):
            group, artifact = resolve(_text(dep, "groupId")), resolve(_text(dep, "artifactId"))
            if _text(dep, "scope") == "import":
                boms.append(f"{group}:{artifact}")
                continue
            managed[f"{group}:{artifact}"] = (_text(dep, "version"), _text(dep, "scope"))

        found: list[ParsedDependency] = []
        for dep in _children(project, "dependencies", "dependency"):
            raw_name = f"{resolve(_text(dep, 'groupId'))}:{resolve(_text(dep, 'artifactId'))}"
            try:
                name = self.normalize_name(raw_name)
            except InvalidPackageNameError as exc:
                result.warnings.append(f"dependency {raw_name}: {exc}, skipped")
                continue
            managed_version, managed_scope = managed.get(name, (None, None))
            scope_text = _text(dep, "scope") or managed_scope or "compile"
            scope = _SCOPES.get(scope_text, DependencyScope.RUNTIME)
            if _text(dep, "optional") == "true" and scope is not DependencyScope.DEVELOPMENT:
                scope = DependencyScope.OPTIONAL
            found.append(
                self._with_version(
                    name, _text(dep, "version") or managed_version, scope, resolve, boms
                )
            )

        if any(True for _ in _children(project, "profiles", "profile", "dependencies")):
            result.warnings.append(
                "dependencies declared inside <profiles> are not imported; "
                "use mvn dependency:list output to include them"
            )
        if any(True for _ in _children(project, "modules", "module")):
            result.warnings.append(
                "this is a multi-module POM: import each module's pom.xml "
                "or the mvn dependency:list output of the whole build"
            )
        result.dependencies = merge_duplicates(found)
        return result

    def _with_version(
        self,
        name: str,
        raw_version: str | None,
        scope: DependencyScope,
        resolve: "_PropertyResolver",
        boms: list[str],
    ) -> ParsedDependency:
        def unresolved(problem: str) -> ParsedDependency:
            return ParsedDependency(name, None, is_exact=False, scope=scope, problem=problem)

        if raw_version is None:
            source = (
                f"the parent POM or an imported BOM ({', '.join(boms)})"
                if boms
                else ("the parent POM")
            )
            return unresolved(f"version not declared, probably managed by {source}")
        version = resolve(raw_version)
        if missing := _PROPERTY_RE.findall(version):
            names = ", ".join(f"${{{m}}}" for m in missing)
            return unresolved(f"property {names} is not defined in this POM")
        try:
            spec = self.parse_spec(version)
        except InvalidVersionSpecError as exc:
            return unresolved(str(exc))
        return ParsedDependency(name, spec.text, spec.is_exact, scope=scope)

    def parse_dependency_list(self, content: str) -> ManifestResult:
        """Parse the output of ``mvn dependency:list`` (console or ``-DoutputFile``)."""
        result = ManifestResult(Ecosystem.MAVEN, DependencySource.MVN_DEPENDENCY_LIST)
        found: list[ParsedDependency] = []
        for line in _ANSI_RE.sub("", content).splitlines():
            match = _LIST_LINE_RE.match(line.strip())
            if not match:
                continue
            parts = match.group(1).split(":")
            # groupId:artifactId:type[:classifier]:version:scope
            group, artifact, version, scope_text = parts[0], parts[1], parts[-2], parts[-1]
            if scope_text not in _SCOPES:
                continue
            scope = _SCOPES[scope_text]
            if "(optional)" in line and scope is not DependencyScope.DEVELOPMENT:
                scope = DependencyScope.OPTIONAL
            # The line pattern only matches characters that form a valid plain version.
            found.append(
                ParsedDependency(
                    f"{group}:{artifact}", version, is_exact=True, scope=scope, is_direct=None
                )
            )
        if not found:
            result.warnings.append(
                "no dependencies found; expected the output of mvn dependency:list"
            )
        result.dependencies = merge_duplicates(found)
        return result


class _PropertyResolver:
    """Expand ``${...}`` placeholders; unknown ones are left in place."""

    def __init__(self, properties: dict[str, str]) -> None:
        self._properties = properties

    def __call__(self, text: str | None) -> str:
        if text is None:
            return ""
        for _ in range(_MAX_PROPERTY_DEPTH):
            expanded = _PROPERTY_RE.sub(lambda m: self._properties.get(m[1], m[0]), text)
            if expanded == text:
                break
            text = expanded
        return text


def _parse_xml(content: str) -> Element:
    try:
        root: Element = fromstring(content)
    except (ParseError, DefusedXmlException) as exc:
        raise ManifestError(f"pom.xml is not valid XML: {exc}") from exc
    if _local(root.tag) != "project":
        raise ManifestError("pom.xml must have a <project> root element")
    return root


def _local(tag: str) -> str:
    """Strip the XML namespace: ``{http://maven.apache.org/POM/4.0.0}project`` -> ``project``."""
    return tag.rpartition("}")[2]


def _child(element: Element, name: str) -> Element | None:
    return next((c for c in element if _local(c.tag) == name), None)


def _children(element: Element, *path: str) -> list[Element]:
    """All elements at ``path`` below ``element``, e.g. ("dependencies", "dependency")."""
    level = [element]
    for name in path:
        level = [c for e in level for c in e if _local(c.tag) == name]
    return level


def _text(element: Element, name: str) -> str | None:
    child = _child(element, name)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def _properties(project: Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    props = _child(project, "properties")
    if props is not None:
        properties.update({_local(p.tag): (p.text or "").strip() for p in props})

    parent = _child(project, "parent")
    for field in ("groupId", "artifactId", "version"):
        parent_value = _text(parent, field) if parent is not None else None
        # groupId and version are inherited from the parent when not declared.
        value = _text(project, field) or (parent_value if field != "artifactId" else None)
        if parent_value is not None:
            properties[f"project.parent.{field}"] = parent_value
            properties[f"parent.{field}"] = parent_value
        if value is not None:
            properties[f"project.{field}"] = value
            properties[f"pom.{field}"] = value  # deprecated Maven 2 aliases
            properties.setdefault(field, value)
    return properties
