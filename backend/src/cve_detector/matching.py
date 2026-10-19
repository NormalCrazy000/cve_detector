"""Decide whether a dependency is affected by an advisory.

Both sides are turned into version intervals: the dependency's spec (a single point for
an exact version) and the advisory's affected ranges for that package (OSV schema). Then:

- every allowed version is affected -> ``affected``;
- some allowed versions are affected -> ``potentially_affected``;
- none -> no finding.

When an advisory lists the package but its ranges cannot be evaluated (e.g. only git
commit ranges, or versions that do not parse), the result is ``potentially_affected``:
better a finding to review than a silent miss.
"""

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from univers.versions import Version

from cve_detector.db.enums import Ecosystem, FindingStatus
from cve_detector.ecosystems import get_handler
from cve_detector.ecosystems.base import EcosystemHandler, InvalidVersionSpecError, VersionSpec
from cve_detector.ecosystems.intervals import Interval, covers, intersects, union
from cve_detector.sources.osv import OSV_ECOSYSTEMS

logger = logging.getLogger(__name__)

# Advisories sometimes use partial versions in ranges ("13.0" for 13.0.0).
_PARTIAL_RE = re.compile(r"^\d+(?:\.\d+)?$")


@dataclass(frozen=True, slots=True)
class AffectedVersions:
    intervals: list[Interval]
    # False when some ranges of the package could not be evaluated.
    complete: bool
    # Whether the advisory mentions the package at all.
    mentioned: bool


def match(
    ecosystem: Ecosystem,
    name: str,
    spec: VersionSpec,
    affected: list[dict[str, Any]],
) -> FindingStatus | None:
    handler = get_handler(ecosystem)
    affected_versions = affected_intervals(handler, ecosystem, name, affected)
    if not affected_versions.mentioned:
        return None
    return evaluate(handler.spec_intervals(spec), affected_versions)


def evaluate(allowed: list[Interval], affected: AffectedVersions) -> FindingStatus | None:
    if not allowed:
        return None
    vulnerable = union(affected.intervals)
    if vulnerable and all(covers(vulnerable, interval) for interval in allowed):
        return FindingStatus.AFFECTED
    if any(intersects(a, v) for a in allowed for v in vulnerable) or not affected.complete:
        return FindingStatus.POTENTIALLY_AFFECTED
    return None


def affected_intervals(
    handler: EcosystemHandler,
    ecosystem: Ecosystem,
    name: str,
    affected: Iterable[dict[str, Any]],
) -> AffectedVersions:
    """Versions of one package affected by an advisory, from OSV ``affected`` entries."""
    intervals: list[Interval] = []
    complete, mentioned = True, False
    for entry in affected:
        package = entry.get("package") or {}
        if package.get("ecosystem") != OSV_ECOSYSTEMS[ecosystem] or package.get("name") != name:
            continue
        mentioned = True
        evaluable = False
        for version_range in entry.get("ranges", []):
            if version_range.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue  # GIT ranges are about commits
            try:
                intervals.extend(_range_intervals(handler, version_range.get("events", [])))
                evaluable = True
            except InvalidVersionSpecError as exc:
                logger.warning("cannot evaluate a range of %s: %s", name, exc)
                complete = False
        for text in entry.get("versions", []):
            try:
                intervals.append(Interval.point(_parse_version(handler, str(text))))
                evaluable = True
            except InvalidVersionSpecError:
                complete = False
        if not evaluable:
            complete = False
    return AffectedVersions(union(intervals), complete, mentioned)


def _range_intervals(handler: EcosystemHandler, events: list[dict[str, str]]) -> list[Interval]:
    """Walk OSV events sorted by version: ``introduced`` opens an interval, ``fixed``
    closes it (excluded) and ``last_affected`` closes it (included)."""
    parsed: list[tuple[str, Version | None]] = []
    for event in events:
        for kind, value in event.items():
            if kind not in ("introduced", "fixed", "last_affected"):
                continue  # "limit" only applies to git ranges
            if kind == "introduced" and value == "0":
                parsed.append((kind, None))
            else:
                parsed.append((kind, _parse_version(handler, value)))
    parsed.sort(key=lambda e: (0,) if e[1] is None else (1, e[1]))

    intervals: list[Interval] = []
    opened = False
    start: Version | None = None
    for kind, version in parsed:
        if kind == "introduced":
            if not opened:
                opened, start = True, version
        elif opened:
            intervals.append(Interval(start, version, upper_inclusive=kind == "last_affected"))
            opened = False
    if opened:
        intervals.append(Interval(start, None))
    return intervals


def _parse_version(handler: EcosystemHandler, text: str) -> Version:
    try:
        return handler.parse_version(text)
    except InvalidVersionSpecError:
        if not _PARTIAL_RE.match(text):
            raise
        return handler.parse_version(".".join([*text.split("."), "0", "0"][:3]))
