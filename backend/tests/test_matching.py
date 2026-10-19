from typing import Any

import pytest

from cve_detector.db.enums import Ecosystem
from cve_detector.db.enums import FindingStatus as Status
from cve_detector.ecosystems import get_handler
from cve_detector.matching import match


def affected(
    name: str,
    *ranges: list[dict[str, str]],
    versions: list[str] | None = None,
    ecosystem: str = "npm",
    range_type: str = "SEMVER",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "package": {"ecosystem": ecosystem, "name": name},
        "ranges": [{"type": range_type, "events": events} for events in ranges],
    }
    if versions is not None:
        entry["versions"] = versions
    return entry


def npm_match(spec: str, entries: list[dict[str, Any]], name: str = "demo") -> Status | None:
    handler = get_handler(Ecosystem.NPM)
    return match(Ecosystem.NPM, name, handler.parse_spec(spec), entries)


# Affected from 1.0.0 (included) to 1.4.0 (fixed) and from 2.0.0 to 2.1.3 (included).
TWO_RANGES = [
    affected(
        "demo",
        [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}],
        [{"introduced": "2.0.0"}, {"last_affected": "2.1.3"}],
    )
]


@pytest.mark.parametrize(
    ("spec", "status"),
    [
        ("0.9.0", None),
        ("1.0.0", Status.AFFECTED),
        ("1.3.9", Status.AFFECTED),
        ("1.4.0", None),
        ("2.1.3", Status.AFFECTED),
        ("2.1.4", None),
        # Ranges: every allowed version affected, some of them, none.
        ("~1.2.0", Status.AFFECTED),
        (">=1.0.0 <1.4.0", Status.AFFECTED),
        ("^1.0.0", Status.POTENTIALLY_AFFECTED),
        ("<=1.0.0", Status.POTENTIALLY_AFFECTED),
        (">=1.4.0 <2.0.0", None),
        ("~2.1.0", Status.POTENTIALLY_AFFECTED),
        ("1.2.x || 2.0.x", Status.AFFECTED),
        ("*", Status.POTENTIALLY_AFFECTED),
    ],
)
def test_two_ranges(spec: str, status: Status | None) -> None:
    assert npm_match(spec, TWO_RANGES) is status


def test_introduced_zero_and_no_fix() -> None:
    entries = [affected("demo", [{"introduced": "0"}])]
    assert npm_match("0.0.1", entries) is Status.AFFECTED
    assert npm_match("*", entries) is Status.AFFECTED


def test_unsorted_events() -> None:
    entries = [affected("demo", [{"fixed": "1.5.0"}, {"introduced": "1.2.0"}])]
    assert npm_match("1.3.0", entries) is Status.AFFECTED
    assert npm_match("1.5.0", entries) is None


def test_explicit_versions_list() -> None:
    entries = [affected("demo", versions=["1.0.0", "1.0.1"])]
    assert npm_match("1.0.1", entries) is Status.AFFECTED
    assert npm_match("1.0.2", entries) is None
    assert npm_match("~1.0.0", entries) is Status.POTENTIALLY_AFFECTED


def test_other_packages_are_ignored() -> None:
    entries = [
        affected("other", [{"introduced": "0"}]),
        affected("demo", [{"introduced": "0"}], ecosystem="PyPI"),
    ]
    assert npm_match("1.0.0", entries) is None


def test_scoped_names_match_exactly() -> None:
    entries = [affected("@example/demo", [{"introduced": "0"}, {"fixed": "2.0.0"}])]
    assert npm_match("1.0.0", entries, name="@example/demo") is Status.AFFECTED


def test_partial_versions_in_advisories() -> None:
    entries = [affected("demo", [{"introduced": "13.0"}, {"fixed": "13.5.1"}])]
    assert npm_match("13.0.0", entries) is Status.AFFECTED
    assert npm_match("12.9.9", entries) is None


def test_unevaluable_ranges_are_potential_findings() -> None:
    git_only = [affected("demo", [{"introduced": "abc123"}, {"fixed": "def456"}], range_type="GIT")]
    assert npm_match("1.0.0", git_only) is Status.POTENTIALLY_AFFECTED

    # A broken range does not hide an affected verdict from a valid one...
    mixed = [
        affected("demo", [{"introduced": "not-a-version"}]),
        affected("demo", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]),
    ]
    assert npm_match("1.5.0", mixed) is Status.AFFECTED
    # ...but outside the valid range the result is uncertain, not "not affected".
    assert npm_match("3.0.0", mixed) is Status.POTENTIALLY_AFFECTED


def test_maven_ecosystem_ranges() -> None:
    handler = get_handler(Ecosystem.MAVEN)
    entries = [
        affected(
            "org.example:demo-lib",
            [{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}],
            [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}],
            ecosystem="Maven",
            range_type="ECOSYSTEM",
        )
    ]

    def status(spec: str) -> Status | None:
        return match(Ecosystem.MAVEN, "org.example:demo-lib", handler.parse_spec(spec), entries)

    assert status("2.0-beta9") is Status.AFFECTED
    assert status("2.0") is Status.AFFECTED
    assert status("2.3.1") is None
    assert status("2.14.1") is Status.AFFECTED
    assert status("[2.13.0,2.15.0)") is Status.AFFECTED
    assert status("[2.10,)") is Status.POTENTIALLY_AFFECTED
    assert status("[2.15.0,)") is None
