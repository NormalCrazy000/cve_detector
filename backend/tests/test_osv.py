import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest

from cve_detector.db.enums import Ecosystem, Severity
from cve_detector.sources.base import AdvisoryRef, PackageRef, SourceError
from cve_detector.sources.osv import OsvSource, advisory_severity, parse_vulnerability

NPM_LIB = PackageRef(Ecosystem.NPM, "example-lib")
MAVEN_LIB = PackageRef(Ecosystem.MAVEN, "org.example:demo-lib")

VULN: dict[str, Any] = {
    "schema_version": "1.6.0",
    "id": "GHSA-test-0001-aaaa",
    "modified": "2026-03-01T10:00:00.123456Z",
    "published": "2026-02-01T09:00:00Z",
    "aliases": ["CVE-2099-0001"],
    "summary": "Prototype pollution in example-lib",
    "details": "Long description.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "example-lib"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
        }
    ],
    "database_specific": {"severity": "HIGH"},
}

Handler = Callable[[httpx2.Request], httpx2.Response]


def make_source(handler: Handler, delays: list[float] | None = None) -> OsvSource:
    return OsvSource(
        transport=httpx2.MockTransport(handler),
        sleep=(delays if delays is not None else []).append,
        retries=2,
    )


def test_list_advisories_batches_and_follows_pagination() -> None:
    requests: list[dict[str, Any]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        requests.append(body)
        results = []
        for query in body["queries"]:
            if query["package"]["name"] == "example-lib" and "page_token" not in query:
                results.append(
                    {
                        "vulns": [{"id": "A-1", "modified": "2026-01-01T00:00:00Z"}],
                        "next_page_token": "page-2",
                    }
                )
            elif query.get("page_token") == "page-2":
                results.append({"vulns": [{"id": "A-2", "modified": "2026-01-02T00:00:00Z"}]})
            else:
                results.append({})
        return httpx2.Response(200, json={"results": results})

    with make_source(handler) as source:
        found = source.list_advisories([NPM_LIB, MAVEN_LIB, NPM_LIB])

    assert found == {
        NPM_LIB: [
            AdvisoryRef("A-1", datetime(2026, 1, 1, tzinfo=UTC)),
            AdvisoryRef("A-2", datetime(2026, 1, 2, tzinfo=UTC)),
        ],
        MAVEN_LIB: [],
    }
    assert requests[0]["queries"] == [
        {"package": {"ecosystem": "npm", "name": "example-lib"}},
        {"package": {"ecosystem": "Maven", "name": "org.example:demo-lib"}},
    ]
    # Only the paginated query is repeated.
    assert requests[1]["queries"] == [
        {"package": {"ecosystem": "npm", "name": "example-lib"}, "page_token": "page-2"}
    ]


def test_list_advisories_rejects_mismatched_results() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"results": []})

    with make_source(handler) as source, pytest.raises(SourceError):
        source.list_advisories([NPM_LIB])


def test_fetch_advisories_skips_missing_ones() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/v1/vulns/GHSA-test-0001-aaaa":
            return httpx2.Response(200, json=VULN)
        return httpx2.Response(404, json={"code": 5, "message": "Bug not found."})

    with make_source(handler) as source:
        records = source.fetch_advisories(["GHSA-test-0001-aaaa", "GONE-1", "GHSA-test-0001-aaaa"])

    assert [r.source_id for r in records] == ["GHSA-test-0001-aaaa"]


def test_retries_transient_errors_with_backoff() -> None:
    responses = iter(
        [
            httpx2.Response(503),
            httpx2.Response(429, headers={"Retry-After": "7"}),
            httpx2.Response(200, json=VULN),
        ]
    )
    delays: list[float] = []
    with make_source(lambda request: next(responses), delays) as source:
        assert source.fetch_advisories(["GHSA-test-0001-aaaa"])
    assert delays == [1.0, 7.0]


def test_retries_network_errors() -> None:
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx2.ConnectError("connection refused")
        return httpx2.Response(200, json=VULN)

    with make_source(handler) as source:
        assert source.fetch_advisories(["GHSA-test-0001-aaaa"])


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx2.Response(503),
        lambda request: httpx2.Response(400, json={"message": "bad request"}),
        lambda request: httpx2.Response(200, content=b"not json"),
    ],
)
def test_gives_up_with_source_error(handler: Handler) -> None:
    with make_source(handler) as source, pytest.raises(SourceError):
        source.fetch_advisories(["GHSA-test-0001-aaaa"])


def test_gives_up_after_repeated_network_errors() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection refused")

    with make_source(handler) as source, pytest.raises(SourceError, match="connection refused"):
        source.list_advisories([NPM_LIB])


def test_parse_vulnerability() -> None:
    record = parse_vulnerability(VULN)

    assert record.source == "osv"
    assert record.source_id == "GHSA-test-0001-aaaa"
    assert record.aliases == ["CVE-2099-0001"]
    assert record.summary == "Prototype pollution in example-lib"
    assert record.severity is Severity.CRITICAL  # CVSS 9.8 beats the HIGH label
    assert record.cvss is not None
    assert record.cvss.score == 9.8
    assert record.modified_at == datetime(2026, 3, 1, 10, 0, 0, 123456, tzinfo=UTC)
    assert record.published_at == datetime(2026, 2, 1, 9, tzinfo=UTC)
    assert record.withdrawn_at is None
    assert record.affected == VULN["affected"]
    assert record.raw == VULN


def test_parse_vulnerability_minimal() -> None:
    record = parse_vulnerability(
        {
            "id": "OSV-TEST-2",
            "details": "\nFirst line.\nSecond line.",
            "withdrawn": "2026-05-01T00:00:00Z",
            "modified": "not a date",
        }
    )
    assert record.summary == "First line."
    assert record.severity is Severity.UNKNOWN
    assert record.cvss is None
    assert record.withdrawn_at == datetime(2026, 5, 1, tzinfo=UTC)
    assert record.modified_at is None


V3_HIGH = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}  # 7.5
V4_MEDIUM = {
    "type": "CVSS_V4",
    "score": "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
}


@pytest.mark.parametrize(
    ("data", "severity", "score"),
    [
        ({}, Severity.UNKNOWN, None),
        ({"database_specific": {"severity": "MODERATE"}}, Severity.MEDIUM, None),
        ({"severity": [V3_HIGH, V4_MEDIUM]}, Severity.HIGH, 7.5),
        # The label wins when it is higher than every CVSS score.
        (
            {"severity": [V4_MEDIUM], "database_specific": {"severity": "CRITICAL"}},
            Severity.CRITICAL,
            V4_MEDIUM,
        ),
        # Severity can also be given per affected package.
        (
            {"affected": [{"severity": [V3_HIGH], "ecosystem_specific": {"severity": "LOW"}}]},
            Severity.HIGH,
            7.5,
        ),
        # Invalid vectors and non-CVSS types are ignored.
        (
            {
                "severity": [
                    {"type": "CVSS_V3", "score": "garbage"},
                    {"type": "Ubuntu", "score": "high"},
                ]
            },
            Severity.UNKNOWN,
            None,
        ),
    ],
)
def test_advisory_severity(
    data: dict[str, Any], severity: Severity, score: float | dict[str, str] | None
) -> None:
    found_severity, cvss = advisory_severity(data)
    assert found_severity is severity
    if isinstance(score, dict):
        assert cvss is not None
        assert cvss.vector == score["score"]
    else:
        assert (cvss.score if cvss else None) == score
