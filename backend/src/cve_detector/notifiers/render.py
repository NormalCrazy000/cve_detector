"""Turn digests and notices into email-ready messages (plain text + HTML).

Templates use no external resources: no images, fonts, scripts or tracking pixels.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from cve_detector.db.enums import FindingStatus, NotificationKind, Severity
from cve_detector.db.models import Finding, Suppression
from cve_detector.matching import fixed_versions
from cve_detector.notifiers.base import Message
from cve_detector.scanning.diff import ChangeKind, FindingChange, ProjectDigest

APP_NAME = "cve_detector"
# Longest list of still-open findings printed in a digest.
MAX_STILL_OPEN = 50

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(enabled_extensions=("html",), default_for_string=False),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)

_STATUS_LABELS = {
    FindingStatus.AFFECTED: "affected",
    FindingStatus.POTENTIALLY_AFFECTED: "potentially affected",
    FindingStatus.FIXED: "no longer affected",
    FindingStatus.WITHDRAWN: "withdrawn",
}
_RESOLUTIONS = {
    FindingStatus.FIXED: "this version is not affected (dependency upgraded or advisory corrected)",
    FindingStatus.WITHDRAWN: "the advisory was withdrawn by its database",
}
# Most important first.
_CHANGE_ORDER = ("status", "severity", "cvss_score", "fixed_versions", "known_exploited")
_SEVERITY_COLORS = {
    Severity.CRITICAL: "#7a1f1f",
    Severity.HIGH: "#b3401a",
    Severity.MEDIUM: "#8a6100",
    Severity.LOW: "#3d6b35",
    Severity.NONE: "#555555",
    Severity.UNKNOWN: "#555555",
}


@dataclass(frozen=True, slots=True)
class FindingView:
    advisory_id: str
    url: str
    aliases: list[str]
    summary: str
    severity: str
    color: str
    cvss_score: float | None
    package: str
    version_spec: str
    status: str
    fixed_versions: list[str]
    known_exploited: bool
    changes: list[str] = field(default_factory=list)
    resolution: str | None = None


@dataclass(frozen=True, slots=True)
class SuppressionView:
    advisory_ref: str
    scope: str
    expires: str
    reason: str


def render_digest(digest: ProjectDigest, kind: NotificationKind, now: datetime) -> Message:
    """The digest (``kind=DIGEST``) or all-clear report (``kind=ALL_CLEAR``) of a project."""
    by_kind: dict[ChangeKind, list[FindingView]] = {k: [] for k in ChangeKind}
    for change in digest.changes:
        by_kind[change.kind].append(_change_view(change))
    reported = {c.finding.id for c in digest.changes}
    still_open = sorted(
        (f for f in digest.open_findings if f.id not in reported),
        key=lambda f: (-f.advisory.severity.rank, f.advisory.source_id),
    )
    context: dict[str, Any] = {
        "app": APP_NAME,
        "project": digest.project.name,
        "all_clear": kind is NotificationKind.ALL_CLEAR,
        "new": by_kind[ChangeKind.NEW],
        "updated": by_kind[ChangeKind.UPDATED],
        "resolved": by_kind[ChangeKind.RESOLVED],
        "still_open": [_finding_view(f) for f in still_open[:MAX_STILL_OPEN]],
        "still_open_more": max(0, len(still_open) - MAX_STILL_OPEN),
        "still_open_counts": _severity_counts(still_open),
        "expiring": [_suppression_view(s) for s in digest.expiring_suppressions],
        "generated": now.strftime("%Y-%m-%d %H:%M UTC"),
    }
    return Message(
        subject=_digest_subject(digest, kind, len(still_open)),
        text=_env.get_template("digest.txt").render(context),
        html=_env.get_template("digest.html").render(context),
    )


def render_notice(title: str, paragraphs: list[str], now: datetime) -> Message:
    """A short message such as a test email or an admin alert."""
    context = {
        "app": APP_NAME,
        "title": title,
        "paragraphs": paragraphs,
        "generated": now.strftime("%Y-%m-%d %H:%M UTC"),
    }
    return Message(
        subject=f"[{APP_NAME}] {title}",
        text=_env.get_template("notice.txt").render(context),
        html=_env.get_template("notice.html").render(context),
    )


def _digest_subject(digest: ProjectDigest, kind: NotificationKind, still_open: int) -> str:
    prefix = f"[{APP_NAME}] {digest.project.name}:"
    if kind is NotificationKind.ALL_CLEAR:
        if still_open:
            return f"{prefix} no new issues, {still_open} still open"
        return f"{prefix} no open vulnerabilities"
    counts = Counter(c.kind for c in digest.changes)
    parts = [f"{counts[k]} {k.value}" for k in ChangeKind if counts[k]]
    serious = _severity_counts(
        [c.finding for c in digest.changes if c.kind is not ChangeKind.RESOLVED],
        only=(Severity.CRITICAL, Severity.HIGH),
    )
    subject = f"{prefix} {', '.join(parts)}"
    if serious:
        subject += f" ({serious})"
    return subject


def _severity_counts(
    findings: list[Finding], only: tuple[Severity, ...] = tuple(reversed(Severity))
) -> str:
    counts = Counter(f.advisory.severity for f in findings)
    return ", ".join(f"{counts[s]} {s.value}" for s in only if counts[s])


def _finding_view(
    finding: Finding, changes: list[str] | None = None, resolution: str | None = None
) -> FindingView:
    advisory = finding.advisory
    dependency = finding.dependency
    library = dependency.library
    return FindingView(
        advisory_id=advisory.source_id,
        url=f"https://osv.dev/vulnerability/{advisory.source_id}",
        aliases=[a for a in advisory.aliases if a != advisory.source_id],
        summary=advisory.summary,
        severity=advisory.severity.value.upper(),
        color=_SEVERITY_COLORS[advisory.severity],
        cvss_score=advisory.cvss_score,
        package=f"{library.ecosystem.value}: {library.name}",
        version_spec=dependency.version_spec,
        status=_STATUS_LABELS[finding.status],
        fixed_versions=fixed_versions(library.ecosystem, library.name, advisory.affected),
        known_exploited=advisory.is_known_exploited,
        changes=changes or [],
        resolution=resolution,
    )


def _change_view(change: FindingChange) -> FindingView:
    finding = change.finding
    if change.kind is ChangeKind.RESOLVED:
        return _finding_view(finding, resolution=_RESOLUTIONS.get(finding.status))
    if change.kind is ChangeKind.UPDATED:
        return _finding_view(finding, changes=_describe_changes(change))
    return _finding_view(finding)


def _describe_changes(change: FindingChange) -> list[str]:
    previous, state = change.previous or {}, change.state
    described = []
    changed = set(change.changed_fields)
    for name in [n for n in _CHANGE_ORDER if n in changed]:
        old, new = previous.get(name), state[name]
        if name == "status":
            old_label = _STATUS_LABELS.get(FindingStatus(old), old) if old else "unknown"
            described.append(f"status: {old_label} → {_STATUS_LABELS[FindingStatus(new)]}")
        elif name == "severity":
            described.append(f"severity: {str(old).upper()} → {str(new).upper()}")
        elif name == "cvss_score":
            described.append(f"CVSS score: {old if old is not None else 'none'} → {new}")
        elif name == "fixed_versions":
            described.append(
                f"fixed in: {', '.join(old or []) or 'none'} → {', '.join(new) or 'none'}"
            )
        elif name == "known_exploited" and new:
            described.append("now known to be exploited in the wild")
    return described or ["advisory details were updated"]


def _suppression_view(suppression: Suppression) -> SuppressionView:
    expires = suppression.expires_at
    return SuppressionView(
        advisory_ref=suppression.advisory_ref,
        scope="all projects" if suppression.project_id is None else "this project",
        expires=expires.strftime("%Y-%m-%d") if expires else "never",
        reason=suppression.reason,
    )
