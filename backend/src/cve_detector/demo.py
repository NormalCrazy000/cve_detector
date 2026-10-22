"""Fill an empty database with a synthetic demo dataset (no network access).

Used by the end-to-end tests and for screenshots: every project, package, address and
advisory is made up (``example.com``, ``DEMO-*`` advisories).

Usage: ``python -m cve_detector.demo``
"""

import sys
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_detector.config_io import import_config
from cve_detector.core.config import get_settings
from cve_detector.cvss import score_vector
from cve_detector.db.base import utcnow
from cve_detector.db.enums import Severity
from cve_detector.db.migrate import upgrade_to_head
from cve_detector.db.models import Project, Suppression
from cve_detector.db.session import get_sessionmaker
from cve_detector.scanning.scan import run_scan
from cve_detector.scanning.suppressions import refresh_suppressions
from cve_detector.sources.base import AdvisoryRecord, AdvisoryRef, PackageRef
from cve_detector.sources.osv import OSV_ECOSYSTEMS

CONFIG = """
version: 1
projects:
  - name: demo-shop
    description: Online shop frontend and API (demo data)
    min_severity: medium
    all_clear_policy: weekly
    recipients: [shop-team@example.com]
    dependencies:
      - {ecosystem: npm, name: demo-http-client, version: 2.3.1}
      - {ecosystem: npm, name: demo-template-engine, version: ^4.1.0}
      - {ecosystem: npm, name: demo-date-utils, version: 1.9.0}
      - {ecosystem: npm, name: demo-test-runner, version: 8.0.2, scope: development}
  - name: demo-billing
    description: Billing service (demo data)
    scan_interval_hours: 12
    recipients: [billing@example.com, oncall@example.com]
    dependencies:
      - {ecosystem: maven, name: "org.example:demo-logging", version: "2.14.1"}
      - {ecosystem: maven, name: "org.example:demo-json", version: "[2.9,2.13)"}
      - {ecosystem: maven, name: "org.example:demo-crypto", version: "1.70"}
  - name: demo-internal-tools
    description: Internal scripts, nothing to report (demo data)
    dependencies:
      - {ecosystem: npm, name: demo-cli-parser, version: 5.0.0}
"""

_VECTORS = {
    Severity.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    Severity.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Severity.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    Severity.LOW: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
}

# (id, ecosystem, package, introduced, fixed, severity, summary)
_ADVISORIES: list[tuple[str, str, str, str, str, Severity, str]] = [
    (
        "DEMO-2026-0001",
        "maven",
        "org.example:demo-logging",
        "2.0.0",
        "2.15.0",
        Severity.CRITICAL,
        "Remote code execution through crafted log messages",
    ),
    (
        "DEMO-2026-0002",
        "npm",
        "demo-http-client",
        "2.0.0",
        "2.4.0",
        Severity.HIGH,
        "Server-side request forgery via redirect handling",
    ),
    (
        "DEMO-2026-0003",
        "npm",
        "demo-template-engine",
        "4.0.0",
        "4.2.5",
        Severity.HIGH,
        "Prototype pollution in template helpers",
    ),
    (
        "DEMO-2026-0004",
        "maven",
        "org.example:demo-json",
        "2.9.0",
        "2.10.0",
        Severity.MEDIUM,
        "Denial of service with deeply nested documents",
    ),
    (
        "DEMO-2026-0005",
        "npm",
        "demo-date-utils",
        "0",
        "2.0.0",
        Severity.LOW,
        "Regular expression denial of service in date parsing",
    ),
    (
        "DEMO-2026-0006",
        "npm",
        "demo-test-runner",
        "8.0.0",
        "8.1.0",
        Severity.MEDIUM,
        "Arbitrary file write in snapshot updates",
    ),
    (
        "DEMO-2026-0007",
        "maven",
        "org.example:demo-crypto",
        "0",
        "1.71",
        Severity.UNKNOWN,
        "Weak default parameters in key derivation",
    ),
]


class DemoSource:
    """A vulnerability source serving the synthetic advisories above."""

    name = "osv"

    def __init__(self) -> None:
        now = utcnow()
        self._records = {
            advisory_id: AdvisoryRecord(
                source=self.name,
                source_id=advisory_id,
                summary=summary,
                severity=severity,
                cvss=score_vector(_VECTORS[severity]) if severity in _VECTORS else None,
                aliases=[advisory_id.replace("DEMO", "CVE-2099")],
                affected=[_affected(ecosystem, package, introduced, fixed)],
                published_at=now - timedelta(days=30),
                modified_at=now - timedelta(days=1),
            )
            for advisory_id, ecosystem, package, introduced, fixed, severity, summary in _ADVISORIES
        }

    def list_advisories(
        self, packages: Sequence[PackageRef]
    ) -> dict[PackageRef, list[AdvisoryRef]]:
        found: dict[PackageRef, list[AdvisoryRef]] = {p: [] for p in packages}
        for record in self._records.values():
            package = record.affected[0]["package"]
            for ref in packages:
                if (OSV_ECOSYSTEMS[ref.ecosystem], ref.name) == (
                    package["ecosystem"],
                    package["name"],
                ):
                    found[ref].append(AdvisoryRef(record.source_id, record.modified_at))
        return found

    def fetch_advisories(self, ids: Sequence[str]) -> list[AdvisoryRecord]:
        return [self._records[i] for i in ids if i in self._records]

    def close(self) -> None:
        pass


def _affected(ecosystem: str, package: str, introduced: str, fixed: str) -> dict[str, Any]:
    return {
        "package": {"ecosystem": "Maven" if ecosystem == "maven" else "npm", "name": package},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}],
    }


def seed_demo(session: Session) -> None:
    """Create the demo projects and scan them with the synthetic advisories."""
    import_config(session, CONFIG)
    session.commit()
    run_scan(session, [DemoSource()], now=utcnow())
    shop = session.scalars(select(Project).where(Project.name == "demo-shop")).one()
    session.add(
        Suppression(
            advisory_ref="CVE-2099-2026-0006",
            project_id=shop.id,
            reason="Test runner only runs in CI with trusted input",
            expires_at=utcnow() + timedelta(days=5),
        )
    )
    session.flush()
    refresh_suppressions(session, utcnow())
    session.commit()


def main() -> int:
    settings = get_settings()
    if settings.database_url is None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    upgrade_to_head(settings.sqlalchemy_url)
    with get_sessionmaker()() as session:
        if session.scalars(select(Project.id)).first() is not None:
            print("the database already has projects; use an empty data directory", file=sys.stderr)
            return 1
        seed_demo(session)
    print(f"demo data written to {settings.sqlalchemy_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
