"""Keep the local advisory store in sync with a vulnerability source."""

import logging
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.db.base import utcnow
from cve_detector.db.models import Advisory, Library
from cve_detector.sources.base import AdvisoryRecord, PackageRef, VulnSource

logger = logging.getLogger(__name__)

_IN_CHUNK = 500


def sync_advisories(
    session: Session, source: VulnSource, libraries: Sequence[Library]
) -> dict[int, list[Advisory]]:
    """Fetch the advisories of each library, downloading only new or changed ones.

    Returns the stored advisories by library id. Each library is queried once even if
    many projects use it.
    """
    packages = {lib.id: PackageRef(lib.ecosystem, lib.name) for lib in libraries}
    refs = source.list_advisories(list(dict.fromkeys(packages.values())))
    wanted = {ref.id: ref for package_refs in refs.values() for ref in package_refs}

    stored = _load(session, source.name, list(wanted))
    stale = [
        advisory_id
        for advisory_id, ref in wanted.items()
        if advisory_id not in stored
        or ref.modified is None
        or stored[advisory_id].modified_at != ref.modified
    ]
    logger.info(
        "%s: %d advisories for %d packages, %d new or changed",
        source.name,
        len(wanted),
        len(refs),
        len(stale),
    )
    for record in source.fetch_advisories(stale):
        stored[record.source_id] = upsert_advisory(session, record, stored.get(record.source_id))
    session.flush()

    return {
        library_id: [stored[r.id] for r in refs.get(package, []) if r.id in stored]
        for library_id, package in packages.items()
    }


def upsert_advisory(
    session: Session, record: AdvisoryRecord, advisory: Advisory | None = None
) -> Advisory:
    if advisory is None:
        advisory = Advisory(source=record.source, source_id=record.source_id)
        session.add(advisory)
    advisory.aliases = record.aliases
    advisory.summary = record.summary
    advisory.severity = record.severity
    advisory.cvss_score = record.cvss.score if record.cvss else None
    advisory.cvss_vector = record.cvss.vector if record.cvss else None
    advisory.affected = record.affected
    advisory.published_at = record.published_at
    advisory.modified_at = record.modified_at
    advisory.withdrawn_at = record.withdrawn_at
    advisory.raw = record.raw
    advisory.fetched_at = utcnow()
    return advisory


def _load(session: Session, source: str, ids: list[str]) -> dict[str, Advisory]:
    found: dict[str, Advisory] = {}
    for start in range(0, len(ids), _IN_CHUNK):
        chunk = ids[start : start + _IN_CHUNK]
        query = select(Advisory).where(Advisory.source == source, Advisory.source_id.in_(chunk))
        found.update((a.source_id, a) for a in session.scalars(query))
    return found
