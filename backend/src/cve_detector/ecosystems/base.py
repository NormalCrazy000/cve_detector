"""Ecosystem interface and the data types shared by manifest parsers."""

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from univers.version_range import VersionRange
from univers.versions import Version

from cve_detector.db.enums import DependencyScope, DependencySource, Ecosystem


class InvalidPackageNameError(ValueError):
    pass


class InvalidVersionSpecError(ValueError):
    pass


class ManifestError(ValueError):
    """The file cannot be parsed at all (wrong format, malformed, unsupported version)."""


@dataclass(frozen=True, slots=True)
class VersionSpec:
    """A validated version or range, in the canonical text form stored in the database."""

    text: str
    is_exact: bool


@dataclass(frozen=True, slots=True)
class ParsedDependency:
    """A dependency found in a manifest, before it is saved.

    ``version_spec`` is ``None`` when the version could not be resolved from the file
    alone (e.g. inherited from a parent POM); ``problem`` says why, and the user must
    complete or discard the entry before saving it.
    """

    name: str
    version_spec: str | None
    is_exact: bool
    scope: DependencyScope = DependencyScope.RUNTIME
    is_direct: bool | None = True
    problem: str | None = None


@dataclass(slots=True)
class ManifestResult:
    ecosystem: Ecosystem
    source: DependencySource
    dependencies: list[ParsedDependency] = field(default_factory=list)
    # Entries that were skipped entirely, e.g. git or local-path dependencies.
    warnings: list[str] = field(default_factory=list)


ManifestParser = Callable[[str], ManifestResult]


class EcosystemHandler(ABC):
    ecosystem: Ecosystem

    @abstractmethod
    def normalize_name(self, name: str) -> str:
        """Return the canonical package name or raise :class:`InvalidPackageNameError`."""

    @abstractmethod
    def parse_version(self, text: str) -> Version:
        """Parse a single concrete version."""

    @abstractmethod
    def parse_spec(self, text: str) -> VersionSpec:
        """Validate a version or range as written by the user or in a manifest.

        Raises :class:`InvalidVersionSpecError`.
        """

    @abstractmethod
    def parse_range(self, spec: VersionSpec) -> VersionRange:
        """Turn a validated spec into a range usable for containment checks."""

    @abstractmethod
    def manifest_parsers(self) -> dict[DependencySource, ManifestParser]:
        """Manifest formats this ecosystem can import."""


def merge_duplicates(dependencies: Iterable[ParsedDependency]) -> list[ParsedDependency]:
    """Collapse entries with the same name and version.

    The same package can be listed several times (nested ``node_modules``, Maven
    classifiers, multi-module builds). The merged entry keeps the most runtime-relevant
    scope and is direct if any occurrence is direct.
    """
    merged: dict[tuple[str, str | None], ParsedDependency] = {}
    for dep in dependencies:
        key = (dep.name, dep.version_spec)
        seen = merged.get(key)
        if seen is None:
            merged[key] = dep
            continue
        is_direct: bool | None
        if seen.is_direct is None or dep.is_direct is None:
            is_direct = seen.is_direct or dep.is_direct or None
        else:
            is_direct = seen.is_direct or dep.is_direct
        merged[key] = replace(
            seen,
            scope=min(seen.scope, dep.scope, key=lambda s: s.rank),
            is_direct=is_direct,
        )
    return sorted(merged.values(), key=lambda d: (d.name, d.version_spec or ""))
