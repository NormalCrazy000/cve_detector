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


class FindingStatus(StrEnum):
    AFFECTED = "affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"


class ScanStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
