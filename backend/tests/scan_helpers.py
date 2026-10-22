"""Fake vulnerability source and builders shared by the scan engine tests."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from cve_detector.cvss import score_vector
from cve_detector.db.enums import Ecosystem, Severity
from cve_detector.sources.base import AdvisoryRecord, AdvisoryRef, PackageRef, SourceError

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)

HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def npm_affected(name: str, introduced: str, fixed: str) -> list[dict[str, Any]]:
    return [
        {
            "package": {"ecosystem": "npm", "name": name},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": introduced}, {"fixed": fixed}]}
            ],
        }
    ]


def record(
    advisory_id: str,
    package: str,
    *,
    introduced: str = "0",
    fixed: str = "2.0.0",
    severity: Severity = Severity.HIGH,
    modified: datetime = T0,
    withdrawn: datetime | None = None,
    aliases: list[str] | None = None,
) -> AdvisoryRecord:
    return AdvisoryRecord(
        source="fake",
        source_id=advisory_id,
        summary=f"summary of {advisory_id}",
        severity=severity,
        cvss=score_vector(HIGH_VECTOR) if severity is Severity.HIGH else None,
        aliases=aliases or [],
        affected=npm_affected(package, introduced, fixed),
        modified_at=modified,
        withdrawn_at=withdrawn,
    )


class FakeSource:
    """Serves a mutable set of advisories; ``fail`` makes every call raise."""

    name = "fake"

    def __init__(self, *records: AdvisoryRecord) -> None:
        self.records = {r.source_id: r for r in records}
        self.fail = False
        self.listed: list[list[PackageRef]] = []
        self.closed = False

    def put(self, *records: AdvisoryRecord) -> None:
        self.records.update((r.source_id, r) for r in records)

    def list_advisories(
        self, packages: Sequence[PackageRef]
    ) -> dict[PackageRef, list[AdvisoryRef]]:
        if self.fail:
            raise SourceError("source unavailable")
        self.listed.append(list(packages))
        return {
            p: [
                AdvisoryRef(r.source_id, r.modified_at)
                for r in self.records.values()
                if any(a["package"]["name"] == p.name for a in r.affected)
                and p.ecosystem is Ecosystem.NPM
            ]
            for p in packages
        }

    def fetch_advisories(self, ids: Sequence[str]) -> list[AdvisoryRecord]:
        return [self.records[i] for i in ids if i in self.records]

    def close(self) -> None:
        self.closed = True
