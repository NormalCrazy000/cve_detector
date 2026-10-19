"""OSV.dev client (https://google.github.io/osv.dev/api/).

Advisories are listed for many packages at once with ``POST /v1/querybatch``, which
returns only ids and modification times; details are then fetched with
``GET /v1/vulns/{id}`` only for advisories that are new or changed.
"""

import logging
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

import httpx2

from cve_detector import __version__
from cve_detector.cvss import CvssScore, InvalidVectorError, score_vector
from cve_detector.db.enums import Ecosystem, Severity
from cve_detector.sources.base import AdvisoryRecord, AdvisoryRef, PackageRef, SourceError

logger = logging.getLogger(__name__)

DEFAULT_URL = "https://api.osv.dev"
OSV_ECOSYSTEMS = {Ecosystem.MAVEN: "Maven", Ecosystem.NPM: "npm"}

_BATCH_SIZE = 500
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_RETRY_DELAY = 60.0
_LABELS = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class OsvSource:
    name = "osv"

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_URL,
        timeout: float = 30.0,
        max_workers: int = 4,
        retries: int = 4,
        transport: httpx2.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = httpx2.Client(
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            headers={"User-Agent": f"cve_detector/{__version__}"},
        )
        self._max_workers = max_workers
        self._retries = retries
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "OsvSource":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def list_advisories(
        self, packages: Sequence[PackageRef]
    ) -> dict[PackageRef, list[AdvisoryRef]]:
        found: dict[PackageRef, list[AdvisoryRef]] = {p: [] for p in packages}
        unique = list(found)
        for start in range(0, len(unique), _BATCH_SIZE):
            pending: list[tuple[PackageRef, str | None]] = [
                (p, None) for p in unique[start : start + _BATCH_SIZE]
            ]
            while pending:
                queries = [_query(package, token) for package, token in pending]
                results = self._request("POST", "/v1/querybatch", {"queries": queries})
                results = results.get("results", [])
                if len(results) != len(pending):
                    raise SourceError("OSV querybatch returned an unexpected number of results")
                next_pending: list[tuple[PackageRef, str | None]] = []
                for (package, _), result in zip(pending, results, strict=True):
                    found[package].extend(
                        AdvisoryRef(v["id"], _parse_time(v.get("modified")))
                        for v in result.get("vulns", [])
                    )
                    if token := result.get("next_page_token"):
                        next_pending.append((package, token))
                pending = next_pending
        return found

    def fetch_advisories(self, ids: Sequence[str]) -> list[AdvisoryRecord]:
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            results = list(pool.map(self._fetch_one, dict.fromkeys(ids)))
        return [r for r in results if r is not None]

    def _fetch_one(self, advisory_id: str) -> AdvisoryRecord | None:
        data = self._request("GET", f"/v1/vulns/{advisory_id}", missing_ok=True)
        if data is None:
            logger.warning("OSV advisory %s no longer exists, skipped", advisory_id)
            return None
        return parse_vulnerability(data)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        missing_ok: bool = False,
    ) -> Any:
        for attempt in range(self._retries + 1):
            last_try = attempt == self._retries
            try:
                response = self._client.request(method, path, json=payload)
            except httpx2.TransportError as exc:
                if last_try:
                    raise SourceError(f"OSV {method} {path} failed: {exc}") from exc
                delay = _backoff(attempt)
            else:
                if response.status_code == 404 and missing_ok:
                    return None
                if response.status_code not in _RETRY_STATUS:
                    if response.is_error:
                        raise SourceError(
                            f"OSV {method} {path} returned HTTP {response.status_code}"
                        )
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise SourceError(f"OSV {method} {path} returned invalid JSON") from exc
                if last_try:
                    raise SourceError(f"OSV {method} {path} returned HTTP {response.status_code}")
                delay = _retry_after(response) or _backoff(attempt)
            logger.info("OSV %s %s failed, retrying in %.0fs", method, path, delay)
            self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover


def parse_vulnerability(data: dict[str, Any]) -> AdvisoryRecord:
    """Normalize an OSV vulnerability (schema 1.x)."""
    severity, cvss = advisory_severity(data)
    summary = data.get("summary") or (data.get("details") or "").strip().split("\n")[0]
    return AdvisoryRecord(
        source=OsvSource.name,
        source_id=data["id"],
        summary=summary[:1000],
        severity=severity,
        cvss=cvss,
        aliases=list(data.get("aliases", [])),
        affected=list(data.get("affected", [])),
        published_at=_parse_time(data.get("published")),
        modified_at=_parse_time(data.get("modified")),
        withdrawn_at=_parse_time(data.get("withdrawn")),
        raw=data,
    )


def advisory_severity(data: dict[str, Any]) -> tuple[Severity, CvssScore | None]:
    """The highest severity among all CVSS vectors and database labels.

    Taking the highest one avoids missing a notification when sources disagree.
    The returned CVSS is the highest scoring vector (newest version on ties).
    """
    entries = [data, *data.get("affected", [])]
    scores: list[CvssScore] = []
    for entry in entries:
        for item in entry.get("severity", []):
            if not str(item.get("type", "")).startswith("CVSS_"):
                continue
            try:
                scores.append(score_vector(str(item.get("score", ""))))
            except InvalidVectorError as exc:
                logger.warning("advisory %s: %s", data.get("id"), exc)

    severities = [s.severity for s in scores]
    for entry in entries:
        for key in ("database_specific", "ecosystem_specific"):
            label = (entry.get(key) or {}).get("severity")
            if isinstance(label, str) and label.upper() in _LABELS:
                severities.append(_LABELS[label.upper()])

    cvss = max(scores, key=lambda s: (s.score, s.version), default=None)
    severity = max(severities, key=lambda s: s.rank, default=Severity.UNKNOWN)
    return severity, cvss


def _query(package: PackageRef, page_token: str | None) -> dict[str, Any]:
    query: dict[str, Any] = {
        "package": {"ecosystem": OSV_ECOSYSTEMS[package.ecosystem], "name": package.name}
    }
    if page_token:
        query["page_token"] = page_token
    return query


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        logger.warning("invalid OSV timestamp %r", value)
        return None


def _backoff(attempt: int) -> float:
    return float(min(2**attempt, _MAX_RETRY_DELAY))


def _retry_after(response: httpx2.Response) -> float | None:
    try:
        return min(float(response.headers["Retry-After"]), _MAX_RETRY_DELAY)
    except (KeyError, ValueError):
        return None
