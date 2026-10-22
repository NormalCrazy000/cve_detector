"""ORM models. See docs/ARCHITECTURE.md, section "Data model"."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cve_detector.db.base import Base, utcnow
from cve_detector.db.enums import (
    AllClearPolicy,
    DependencyScope,
    DependencySource,
    Ecosystem,
    EmailDelivery,
    FindingStatus,
    NotificationKind,
    ScanStatus,
    Severity,
)


def _enum[E: StrEnum](enum_cls: type[E]) -> Enum:
    return Enum(
        enum_cls,
        native_enum=False,
        length=32,
        values_callable=lambda members: [m.value for m in members],
        validate_strings=True,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class Project(TimestampMixin, Base):
    __tablename__ = "project"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    scan_interval_hours: Mapped[int] = mapped_column(default=24)
    min_severity: Mapped[Severity] = mapped_column(_enum(Severity), default=Severity.LOW)
    all_clear_policy: Mapped[AllClearPolicy] = mapped_column(
        _enum(AllClearPolicy), default=AllClearPolicy.NEVER
    )
    email_delivery: Mapped[EmailDelivery] = mapped_column(
        _enum(EmailDelivery), default=EmailDelivery.SEPARATE
    )
    # Dependency scopes that are notified; findings of the others are kept but not sent.
    included_scopes: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: [s.value for s in DependencyScope]
    )
    # Also notify advisory changes that are not significant (new links, reworded text).
    notify_minor_updates: Mapped[bool] = mapped_column(default=False)
    last_scan_at: Mapped[datetime | None]
    # None: due immediately (e.g. a project that was never scanned).
    next_scan_at: Mapped[datetime | None]
    last_scan_error: Mapped[str | None] = mapped_column(Text)
    # Last time a digest or all-clear report reached at least one recipient.
    last_notified_at: Mapped[datetime | None]

    recipients: Mapped[list["Recipient"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["Dependency"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Recipient(Base):
    __tablename__ = "recipient"
    __table_args__ = (UniqueConstraint("project_id", "channel", "target"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    channel: Mapped[str] = mapped_column(String(32), default="email")
    target: Mapped[str] = mapped_column(String(320))

    project: Mapped[Project] = relationship(back_populates="recipients")


class Library(Base):
    """Shared catalog: each ``ecosystem + name`` exists once across all projects."""

    __tablename__ = "library"
    __table_args__ = (UniqueConstraint("ecosystem", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[Ecosystem] = mapped_column(_enum(Ecosystem))
    name: Mapped[str] = mapped_column(String(400))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    dependencies: Mapped[list["Dependency"]] = relationship(back_populates="library")


class Dependency(TimestampMixin, Base):
    __tablename__ = "dependency"
    __table_args__ = (UniqueConstraint("project_id", "library_id", "version_spec"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    library_id: Mapped[int] = mapped_column(ForeignKey("library.id", ondelete="RESTRICT"))
    version_spec: Mapped[str] = mapped_column(String(200))
    is_exact: Mapped[bool]
    source: Mapped[DependencySource] = mapped_column(
        _enum(DependencySource), default=DependencySource.MANUAL
    )
    scope: Mapped[DependencyScope] = mapped_column(
        _enum(DependencyScope), default=DependencyScope.RUNTIME
    )
    # None when the source cannot tell (e.g. ``mvn dependency:list`` output).
    is_direct: Mapped[bool | None] = mapped_column(default=True)

    project: Mapped[Project] = relationship(back_populates="dependencies")
    library: Mapped[Library] = relationship(back_populates="dependencies")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan"
    )


class Advisory(Base):
    __tablename__ = "advisory"
    __table_args__ = (UniqueConstraint("source", "source_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str] = mapped_column(String(100))
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(_enum(Severity), default=Severity.UNKNOWN)
    cvss_score: Mapped[float | None]
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    affected: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None]
    modified_at: Mapped[datetime | None]
    withdrawn_at: Mapped[datetime | None]
    is_known_exploited: Mapped[bool] = mapped_column(default=False)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="advisory")


class Finding(Base):
    __tablename__ = "finding"
    __table_args__ = (UniqueConstraint("dependency_id", "advisory_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependency.id", ondelete="CASCADE"))
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisory.id", ondelete="CASCADE"))
    status: Mapped[FindingStatus] = mapped_column(_enum(FindingStatus))
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    resolved_at: Mapped[datetime | None]
    # The active suppression silencing this finding, refreshed on every scan.
    suppression_id: Mapped[int | None] = mapped_column(
        ForeignKey("suppression.id", ondelete="SET NULL")
    )
    # What the recipients were last told (see ``scanning.diff.finding_state``);
    # None when they were never told, or the finding was suppressed since.
    notified_state: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    dependency: Mapped[Dependency] = relationship(back_populates="findings")
    advisory: Mapped[Advisory] = relationship(back_populates="findings")
    suppression: Mapped["Suppression | None"] = relationship()


class Suppression(Base):
    """Silences an advisory (by OSV id or alias such as a CVE id), globally or per project."""

    __tablename__ = "suppression"

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_ref: Mapped[str] = mapped_column(String(100), index=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None]


class ScanRun(Base):
    __tablename__ = "scan_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None]
    status: Mapped[ScanStatus] = mapped_column(_enum(ScanStatus), default=ScanStatus.RUNNING)
    projects_scanned: Mapped[int] = mapped_column(default=0)
    libraries_queried: Mapped[int] = mapped_column(default=0)
    findings_new: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text)


class NotificationLog(Base):
    """One delivery attempt: a message sent to one or more targets of a channel."""

    __tablename__ = "notification_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    # None for messages not about a project (test emails, admin alerts).
    project_id: Mapped[int | None] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    kind: Mapped[NotificationKind] = mapped_column(_enum(NotificationKind))
    channel: Mapped[str] = mapped_column(String(32))
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    sent_at: Mapped[datetime] = mapped_column(default=utcnow)
    content_hash: Mapped[str] = mapped_column(String(64))
    success: Mapped[bool]
    error: Mapped[str | None] = mapped_column(Text)


class AdminSession(Base):
    """A logged-in browser. Only a hash of the cookie token is stored."""

    __tablename__ = "admin_session"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
