"""Vulnerability source interface and the normalized advisory it produces."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from cve_detector.cvss import CvssScore
from cve_detector.db.enums import Ecosystem, Severity


class SourceError(RuntimeError):
    """The source could not be queried (network, HTTP or format error)."""


@dataclass(frozen=True, slots=True)
class PackageRef:
    ecosystem: Ecosystem
    name: str


@dataclass(frozen=True, slots=True)
class AdvisoryRef:
    """Identifies an advisory and its revision, without the details."""

    id: str
    modified: datetime | None


@dataclass(frozen=True, slots=True)
class AdvisoryRecord:
    """An advisory normalized for storage.

    ``affected`` keeps the OSV schema (``package``, ``ranges``, ``versions``), which is
    also what other sources are converted to.
    """

    source: str
    source_id: str
    summary: str
    severity: Severity
    cvss: CvssScore | None
    aliases: list[str] = field(default_factory=list)
    affected: list[dict[str, Any]] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    withdrawn_at: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class VulnSource(Protocol):
    name: str

    def list_advisories(
        self, packages: Sequence[PackageRef]
    ) -> dict[PackageRef, list[AdvisoryRef]]:
        """Advisories that mention each package, with their last modification time."""
        ...

    def fetch_advisories(self, ids: Sequence[str]) -> list[AdvisoryRecord]:
        """Full details of the given advisories; unknown ids are skipped."""
        ...

    def close(self) -> None:
        """Release network resources."""
        ...
