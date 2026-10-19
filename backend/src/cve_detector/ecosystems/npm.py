"""npm: package names, semver ranges, ``package.json`` and ``package-lock.json``."""

import json
import re
from typing import Any

from univers.version_range import NpmVersionRange, VersionRange
from univers.versions import SemverVersion, Version

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

# Old packages may contain uppercase letters, so the check is case-insensitive.
_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.IGNORECASE)
_MAX_NAME_LENGTH = 214
_PRERELEASE = r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
_EXACT_RE = re.compile(rf"^v?\d+\.\d+\.\d+{_PRERELEASE}$")
# One comparator of a range: optional operator, then a version that may be partial ("1.2")
# or contain wildcards ("1.x", "1.2.*").
_OPERATORS = r"<=|>=|<|>|=|~>|~|\^"
_PART = r"(?:\d+|[xX*])"
_COMPARATOR_RE = re.compile(
    rf"^(?P<op>{_OPERATORS})?v?(?P<version>{_PART}(?:\.{_PART}(?:\.{_PART}{_PRERELEASE})?)?)$"
)
_OPERATOR_SPACE_RE = re.compile(rf"({_OPERATORS})\s+")
_DIST_TAG_RE = re.compile(r"^[A-Za-z][\w.-]*$")
# Specs that point outside the registry: nothing to look up in vulnerability databases.
_NON_REGISTRY_PREFIXES = (
    "git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:",
    "file:", "link:", "workspace:", "portal:", "patch:", "http:", "https:",
)  # fmt: skip

# package.json sections, most runtime-relevant first so duplicates keep the stronger scope.
_SECTIONS = {
    "dependencies": DependencyScope.RUNTIME,
    "peerDependencies": DependencyScope.PROVIDED,
    "optionalDependencies": DependencyScope.OPTIONAL,
    "devDependencies": DependencyScope.DEVELOPMENT,
}


class NpmHandler(EcosystemHandler):
    ecosystem = Ecosystem.NPM

    def normalize_name(self, name: str) -> str:
        name = name.strip()
        if len(name) > _MAX_NAME_LENGTH or not _NAME_RE.match(name):
            raise InvalidPackageNameError(f"invalid npm package name: {name!r}")
        return name

    def parse_version(self, text: str) -> Version:
        text = text.strip().lstrip("=")
        if not _EXACT_RE.match(text):
            raise InvalidVersionSpecError(f"invalid npm version: {text!r}")
        return SemverVersion(text.removeprefix("v"))

    def parse_spec(self, text: str) -> VersionSpec:
        text = _OPERATOR_SPACE_RE.sub(r"\1", " ".join(text.split()))
        exact = text.lstrip("=")
        if _EXACT_RE.match(exact):
            return VersionSpec(exact.removeprefix("v"), is_exact=True)
        spec = VersionSpec(text or "*", is_exact=False)
        self.parse_range(spec)
        return spec

    def parse_range(self, spec: VersionSpec) -> VersionRange:
        native = spec.text if spec.is_exact else _to_univers(spec.text)
        try:
            version_range: VersionRange = NpmVersionRange.from_native(native)  # type: ignore[no-untyped-call]
        except Exception as exc:
            raise InvalidVersionSpecError(f"invalid npm version range: {spec.text!r}") from exc
        return version_range

    def manifest_parsers(self) -> dict[DependencySource, ManifestParser]:
        return {
            DependencySource.PACKAGE_JSON: self.parse_package_json,
            DependencySource.PACKAGE_LOCK: self.parse_package_lock,
        }

    def parse_package_json(self, content: str) -> ManifestResult:
        data = _load_json_object(content, "package.json")
        result = ManifestResult(Ecosystem.NPM, DependencySource.PACKAGE_JSON)
        found: list[ParsedDependency] = []
        optional_peers = {
            name
            for name, meta in _section(data, "peerDependenciesMeta").items()
            if isinstance(meta, dict) and meta.get("optional") is True
        }
        for section, section_scope in _SECTIONS.items():
            for alias, raw_spec in _section(data, section).items():
                scope = section_scope
                if section == "peerDependencies" and alias in optional_peers:
                    scope = DependencyScope.OPTIONAL
                dep = self._parse_declared(alias, raw_spec, scope, section, result.warnings)
                if dep is not None:
                    found.append(dep)
        result.dependencies = merge_duplicates(found)
        return result

    def _parse_declared(
        self,
        alias: str,
        raw_spec: Any,
        scope: DependencyScope,
        section: str,
        warnings: list[str],
    ) -> ParsedDependency | None:
        where = f"{section}.{alias}"
        if not isinstance(raw_spec, str):
            warnings.append(f"{where}: version is not a string, skipped")
            return None
        name, spec_text = alias, raw_spec.strip()
        if spec_text.startswith("npm:"):  # alias: "npm:real-name@spec"
            target = spec_text.removeprefix("npm:")
            at = target.rfind("@")
            if at > 0:
                name, spec_text = target[:at], target[at + 1 :]
            else:
                name, spec_text = target, "*"
        if spec_text.startswith(_NON_REGISTRY_PREFIXES) or _is_github_shorthand(spec_text):
            warnings.append(f"{where}: {spec_text!r} is not an npm registry package, skipped")
            return None
        try:
            name = self.normalize_name(name)
        except InvalidPackageNameError as exc:
            warnings.append(f"{where}: {exc}, skipped")
            return None
        try:
            spec = self.parse_spec(spec_text)
        except InvalidVersionSpecError:
            if _DIST_TAG_RE.match(spec_text):
                problem = f"dist-tag {spec_text!r} is not a version, enter one"
            else:
                problem = f"unsupported version {spec_text!r}, enter a version or range"
            return ParsedDependency(name, None, is_exact=False, scope=scope, problem=problem)
        return ParsedDependency(name, spec.text, spec.is_exact, scope=scope)

    def parse_package_lock(self, content: str) -> ManifestResult:
        data = _load_json_object(content, "package-lock.json")
        version = data.get("lockfileVersion")
        packages = data.get("packages")
        if version not in (2, 3) or not isinstance(packages, dict):
            raise ManifestError(
                f"unsupported package-lock.json (lockfileVersion {version!r}); "
                "regenerate it with npm 7 or later"
            )
        result = ManifestResult(Ecosystem.NPM, DependencySource.PACKAGE_LOCK)
        direct = _direct_names(packages)
        found: list[ParsedDependency] = []
        for path, entry in packages.items():
            if "node_modules/" not in path or not isinstance(entry, dict) or entry.get("link"):
                continue  # root, workspace folders and symlinks to them
            prefix, _, alias = path.rpartition("node_modules/")
            name = entry.get("name") or alias
            resolved = entry.get("resolved", "")
            if isinstance(resolved, str) and resolved.startswith(("git+", "file:")):
                result.warnings.append(f"{path}: not an npm registry package, skipped")
                continue
            try:
                name = self.normalize_name(name)
                spec = self.parse_spec(str(entry.get("version", "")))
            except (InvalidPackageNameError, InvalidVersionSpecError) as exc:
                result.warnings.append(f"{path}: {exc}, skipped")
                continue
            if not spec.is_exact:
                result.warnings.append(f"{path}: no exact version, skipped")
                continue
            is_top_level = "node_modules/" not in prefix
            found.append(
                ParsedDependency(
                    name,
                    spec.text,
                    is_exact=True,
                    scope=_lock_scope(entry),
                    is_direct=is_top_level and alias in direct,
                )
            )
        result.dependencies = merge_duplicates(found)
        return result


def _to_univers(text: str) -> str:
    """Rewrite an npm range into the subset univers parses correctly.

    univers accepts some invalid input (">>1"), reads partial versions as exact ("1.2"
    becomes 1.2.0 instead of 1.2.x) and mangles wildcards ("1.*"). Each comparator is
    validated here and partial or wildcard versions are expanded with npm semantics.
    """
    alternatives = []
    for alternative in text.split("||"):
        tokens = alternative.split()
        if len(tokens) == 3 and tokens[1] == "-":  # hyphen range "1.2.3 - 2.3.4"
            if not all(_EXACT_RE.match(t) for t in tokens[::2]):
                raise InvalidVersionSpecError(
                    f"invalid npm version range: {text!r} (use full versions around ' - ')"
                )
            alternatives.append(alternative.strip())
            continue
        alternatives.append(" ".join(_comparator(t, text) for t in tokens) or "*")
    return " || ".join(alternatives)


def _comparator(token: str, text: str) -> str:
    match = _COMPARATOR_RE.match(token)
    if not match:
        raise InvalidVersionSpecError(f"invalid npm version range: {text!r}")
    op = (match["op"] or "").replace("~>", "~")
    parts = match["version"].split(".", 2)
    # Index of the first missing or wildcard part, None for a full version.
    loose = next((i for i, p in enumerate([*parts, "x", "x"][:3]) if p in ("x", "X", "*")), None)
    if loose is None:
        return op + match["version"]
    fixed = [int(p) for p in parts[:loose]]
    if loose == 0:
        return "*"
    if op in ("", "=") or (op == "^" and not any(fixed)):
        return ".".join(map(str, fixed)) + ".x"  # "1.2" -> "1.2.x", "^0.x" -> "0.x"
    if op in (">", "<="):
        # ">1.2" means ">=1.3.0" and "<=1.2" means "<1.3.0".
        fixed[-1] += 1
        op = ">=" if op == ">" else "<"
    return op + ".".join(map(str, fixed + [0] * (3 - loose)))


def _is_github_shorthand(spec: str) -> bool:
    """``user/repo`` or ``user/repo#ref``: never a semver range."""
    return "/" in spec and " " not in spec


def _load_json_object(content: str, filename: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{filename} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{filename} must contain a JSON object")
    return data


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _direct_names(packages: dict[str, Any]) -> set[str]:
    """Names declared by the root package or by any workspace package."""
    names: set[str] = set()
    for path, entry in packages.items():
        if "node_modules/" in path or not isinstance(entry, dict):
            continue
        for section in _SECTIONS:
            names.update(_section(entry, section))
    return names


def _lock_scope(entry: dict[str, Any]) -> DependencyScope:
    if entry.get("dev") or entry.get("devOptional"):
        return DependencyScope.DEVELOPMENT
    if entry.get("optional"):
        return DependencyScope.OPTIONAL
    if entry.get("peer"):
        return DependencyScope.PROVIDED
    return DependencyScope.RUNTIME
