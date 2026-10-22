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


class EmailDelivery(StrEnum):
    """How a project's email recipients receive a message."""

    SEPARATE = "separate"  # one private message per recipient
    TOGETHER = "together"  # one message with every recipient in "To"


class NotificationKind(StrEnum):
    DIGEST = "digest"
    ALL_CLEAR = "all_clear"
    TEST = "test"
    ADMIN_ALERT = "admin_alert"


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
    """Result of matching a dependency against an advisory.

    ``fixed`` means the advisory no longer matches (its ranges were corrected or the
    package was removed from it); ``withdrawn`` means the database retracted it.
    Suppressions do not change the status, see ``Finding.suppression_id``.
    """

    AFFECTED = "affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    FIXED = "fixed"
    WITHDRAWN = "withdrawn"

    @property
    def is_open(self) -> bool:
        return self in (FindingStatus.AFFECTED, FindingStatus.POTENTIALLY_AFFECTED)


class ScanStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
