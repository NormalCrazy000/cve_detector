from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.advisories import sync_advisories
from cve_detector.catalog import get_or_create_library
from cve_detector.cvss import score_vector
from cve_detector.db.enums import Ecosystem, Severity
from cve_detector.db.models import Advisory
from cve_detector.sources.base import AdvisoryRecord, AdvisoryRef, PackageRef

T1 = datetime(2026, 1, 1, tzinfo=UTC)
T2 = datetime(2026, 2, 1, tzinfo=UTC)


class FakeSource:
    name = "fake"

    def __init__(self) -> None:
        self.advisories: dict[PackageRef, list[AdvisoryRef]] = {}
        self.listed: list[list[PackageRef]] = []
        self.fetched: list[list[str]] = []

    def list_advisories(
        self, packages: Sequence[PackageRef]
    ) -> dict[PackageRef, list[AdvisoryRef]]:
        self.listed.append(list(packages))
        return {p: self.advisories.get(p, []) for p in packages}

    def fetch_advisories(self, ids: Sequence[str]) -> list[AdvisoryRecord]:
        self.fetched.append(list(ids))
        modified = {r.id: r.modified for refs in self.advisories.values() for r in refs}
        return [
            AdvisoryRecord(
                source=self.name,
                source_id=i,
                summary=f"summary of {i} at {modified[i] or T1:%Y-%m}",
                severity=Severity.HIGH,
                cvss=score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                aliases=[f"CVE-2099-{i}"],
                modified_at=modified[i],
            )
            for i in ids
            if i != "GONE"
        ]


def test_sync_fetches_only_new_or_changed_advisories(session: Session) -> None:
    lib_a = get_or_create_library(session, Ecosystem.NPM, "example-a")
    lib_b = get_or_create_library(session, Ecosystem.NPM, "example-b")
    pkg_a, pkg_b = PackageRef(Ecosystem.NPM, "example-a"), PackageRef(Ecosystem.NPM, "example-b")
    source = FakeSource()
    # "SHARED" affects both libraries, "GONE" disappears between listing and fetching.
    source.advisories = {
        pkg_a: [AdvisoryRef("ONE", T1), AdvisoryRef("SHARED", T1), AdvisoryRef("GONE", T1)],
        pkg_b: [AdvisoryRef("SHARED", T1)],
    }

    first = sync_advisories(session, source, [lib_a, lib_b, lib_a])
    session.commit()

    assert source.listed == [[pkg_a, pkg_b]]
    assert source.fetched == [["ONE", "SHARED", "GONE"]]
    assert [a.source_id for a in first[lib_a.id]] == ["ONE", "SHARED"]
    assert [a.source_id for a in first[lib_b.id]] == ["SHARED"]
    stored = session.scalars(select(Advisory).where(Advisory.source_id == "ONE")).one()
    assert stored.severity is Severity.HIGH
    assert stored.cvss_score == 7.5
    assert stored.aliases == ["CVE-2099-ONE"]
    assert stored.modified_at == T1

    # Second run: only the advisory modified upstream is downloaded again.
    source.advisories[pkg_a][0] = AdvisoryRef("ONE", T2)
    second = sync_advisories(session, source, [lib_a, lib_b])
    session.commit()

    assert source.fetched[-1] == ["ONE", "GONE"]
    assert second[lib_a.id][0] is stored
    assert stored.summary == "summary of ONE at 2026-02"
    assert len(session.scalars(select(Advisory)).all()) == 2


def test_sync_refetches_advisories_without_modification_time(session: Session) -> None:
    lib = get_or_create_library(session, Ecosystem.NPM, "example-a")
    source = FakeSource()
    source.advisories = {PackageRef(Ecosystem.NPM, "example-a"): [AdvisoryRef("ONE", None)]}

    sync_advisories(session, source, [lib])
    sync_advisories(session, source, [lib])

    assert source.fetched == [["ONE"], ["ONE"]]
