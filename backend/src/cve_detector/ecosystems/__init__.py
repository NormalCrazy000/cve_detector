"""Supported package ecosystems and manifest formats."""

from pathlib import PurePosixPath

from cve_detector.db.enums import DependencySource, Ecosystem
from cve_detector.ecosystems.base import EcosystemHandler, ManifestError, ManifestResult
from cve_detector.ecosystems.maven import MavenHandler
from cve_detector.ecosystems.npm import NpmHandler

_HANDLERS: dict[Ecosystem, EcosystemHandler] = {
    handler.ecosystem: handler for handler in (MavenHandler(), NpmHandler())
}

# Formats that can be recognized by file name; mvn dependency:list output has none.
_FILENAMES = {
    "pom.xml": DependencySource.POM_XML,
    "package.json": DependencySource.PACKAGE_JSON,
    "package-lock.json": DependencySource.PACKAGE_LOCK,
    "npm-shrinkwrap.json": DependencySource.PACKAGE_LOCK,
}


def get_handler(ecosystem: Ecosystem) -> EcosystemHandler:
    return _HANDLERS[ecosystem]


def detect_source(filename: str) -> DependencySource | None:
    name = PurePosixPath(filename.replace("\\", "/")).name.lower()
    if name.endswith(".pom"):
        return DependencySource.POM_XML
    return _FILENAMES.get(name)


def parse_manifest(source: DependencySource, content: str) -> ManifestResult:
    """Parse a manifest of a known format. Raises :class:`ManifestError`."""
    for handler in _HANDLERS.values():
        parser = handler.manifest_parsers().get(source)
        if parser is not None:
            return parser(content)
    raise ManifestError(f"{source.value} is not a manifest format")
