"""Decide what to tell a project's recipients after a scan.

Each finding remembers the state its recipients were last told about
(``Finding.notified_state``). Comparing it with the current state gives:

- ``new``: an open finding they were never told about (or told it was resolved);
- ``updated``: a significant change (status, severity, CVSS score, fixed versions,
  known exploitation) or, when the project opts in, any change to the advisory;
- ``resolved``: a finding they were told about is no longer open.

Only findings that pass the project's filters are reported: not suppressed, an
included dependency scope and a severity at or above the threshold (``unknown``
always passes). The others are still stored and shown in the UI.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from cve_detector.db.enums import FindingStatus, Severity
from cve_detector.db.models import Finding, Project, Suppression
from cve_detector.matching import fixed_versions

# Advisory revision; only compared when the project wants minor updates too.
_MINOR_KEY = "modified"


class ChangeKind(StrEnum):
    NEW = "new"
    UPDATED = "updated"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class FindingChange:
    kind: ChangeKind
    finding: Finding
    state: dict[str, Any]
    # What was notified before, None for new findings.
    previous: dict[str, Any] | None = None

    @property
    def changed_fields(self) -> list[str]:
        if self.previous is None:
            return []
        return sorted(k for k, v in self.state.items() if self.previous.get(k) != v)


@dataclass(slots=True)
class ProjectDigest:
    project: Project
    changes: list[FindingChange] = field(default_factory=list)
    # Every open finding that passes the filters, reported or not.
    open_findings: list[Finding] = field(default_factory=list)
    expiring_suppressions: list[Suppression] = field(default_factory=list)

    @property
    def has_news(self) -> bool:
        return bool(self.changes or self.expiring_suppressions)


def finding_state(finding: Finding) -> dict[str, Any]:
    advisory = finding.advisory
    library = finding.dependency.library
    modified = advisory.modified_at
    return {
        "status": finding.status.value,
        "severity": advisory.severity.value,
        "cvss_score": advisory.cvss_score,
        "fixed_versions": fixed_versions(library.ecosystem, library.name, advisory.affected),
        "known_exploited": advisory.is_known_exploited,
        _MINOR_KEY: modified.isoformat() if modified else None,
    }


def is_reportable(project: Project, finding: Finding) -> bool:
    if finding.suppression is not None:
        return False
    if finding.dependency.scope not in project.included_scopes:
        return False
    severity = finding.advisory.severity
    return severity is Severity.UNKNOWN or severity.rank >= project.min_severity.rank


def diff_project(
    project: Project,
    findings: list[Finding],
    expiring_suppressions: list[Suppression] | None = None,
) -> ProjectDigest:
    digest = ProjectDigest(project, expiring_suppressions=expiring_suppressions or [])
    for finding in findings:
        if not is_reportable(project, finding):
            continue
        change = _change(project, finding)
        if finding.status.is_open:
            digest.open_findings.append(finding)
        if change is not None:
            digest.changes.append(change)
    digest.changes.sort(
        key=lambda c: (-Severity(c.state["severity"]).rank, c.finding.advisory.source_id)
    )
    return digest


def mark_notified(digest: ProjectDigest) -> None:
    """Record that the digest reached the recipients; call only after a successful send."""
    for change in digest.changes:
        change.finding.notified_state = change.state


def _change(project: Project, finding: Finding) -> FindingChange | None:
    state = finding_state(finding)
    previous = finding.notified_state
    was_open = previous is not None and FindingStatus(previous["status"]).is_open
    if not finding.status.is_open:
        return FindingChange(ChangeKind.RESOLVED, finding, state, previous) if was_open else None
    if previous is None or not was_open:
        return FindingChange(ChangeKind.NEW, finding, state)
    if _significant(previous) != _significant(state) or (
        project.notify_minor_updates and previous.get(_MINOR_KEY) != state[_MINOR_KEY]
    ):
        return FindingChange(ChangeKind.UPDATED, finding, state, previous)
    return None


def _significant(state: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in state.items() if k != _MINOR_KEY}
