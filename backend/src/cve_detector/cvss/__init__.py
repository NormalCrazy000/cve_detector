"""CVSS base scores (v2, v3.x, v4.0) and their qualitative severity."""

from dataclasses import dataclass

from cve_detector.cvss import v2, v3, v4
from cve_detector.cvss.base import InvalidVectorError
from cve_detector.db.enums import Severity

__all__ = ["CvssScore", "InvalidVectorError", "score_vector", "severity_for_score"]


@dataclass(frozen=True, slots=True)
class CvssScore:
    version: int  # major version: 2, 3 or 4
    score: float
    vector: str

    @property
    def severity(self) -> Severity:
        return severity_for_score(self.score, self.version)


def score_vector(vector: str) -> CvssScore:
    """Compute the base score of a vector, detecting its version from the prefix.

    Raises :class:`InvalidVectorError`.
    """
    vector = vector.strip()
    if vector.startswith(v4.PREFIX):
        return CvssScore(4, v4.score(vector), vector)
    if vector.startswith("CVSS:3."):
        return CvssScore(3, v3.score(vector), vector)
    return CvssScore(2, v2.score(vector), vector)


def severity_for_score(score: float, version: int = 3) -> Severity:
    """Qualitative rating: v3/v4 scale from the specification, v2 scale used by NVD."""
    if version == 2:
        if score >= 7.0:
            return Severity.HIGH
        return Severity.MEDIUM if score >= 4.0 else Severity.LOW
    if score == 0:
        return Severity.NONE
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    return Severity.MEDIUM if score >= 4.0 else Severity.LOW
