"""Enumerations persisted in the database (stored by value)."""

from enum import StrEnum


class Ecosystem(StrEnum):
    MAVEN = "maven"
    NPM = "npm"


class Severity(StrEnum):
    """Ordered from least to most severe; compare with :meth:`rank`."""

    UNKNOWN = "unknown"
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class AllClearPolicy(StrEnum):
    NEVER = "never"
    EVERY_RUN = "every_run"
    DAILY = "daily"
    WEEKLY = "weekly"


class DependencySource(StrEnum):
    MANUAL = "manual"
    POM_XML = "pom.xml"
    PACKAGE_JSON = "package.json"
    PACKAGE_LOCK = "package-lock.json"
    MVN_DEPENDENCY_LIST = "mvn-dependency-list"


class DependencyScope(StrEnum):
    """Where a dependency is used, normalized across ecosystems.

    Ordered from most to least relevant at runtime; see :meth:`rank`.
    Maven ``compile``/``runtime`` and npm ``dependencies`` map to ``runtime``;
    Maven ``provided``/``system`` and npm ``peerDependencies`` to ``provided``;
    Maven ``<optional>`` and npm ``optionalDependencies`` to ``optional``;
    Maven ``test`` and npm ``devDependencies`` to ``development``.
    """

    RUNTIME = "runtime"
    PROVIDED = "provided"
    OPTIONAL = "optional"
    DEVELOPMENT = "development"

    @property
    def rank(self) -> int:
        return list(DependencyScope).index(self)


class FindingStatus(StrEnum):
    AFFECTED = "affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"


class ScanStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
