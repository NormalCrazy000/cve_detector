from pathlib import Path

import pytest

from cve_detector.cvss import InvalidVectorError, score_vector, severity_for_score
from cve_detector.db.enums import Severity

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # Temporal metrics are accepted and do not change the base score.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:O", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
        ("(AV:N/AC:L/Au:N/C:C/I:C/A:C)", 10.0),
        ("AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3),
        ("AV:L/AC:L/Au:N/C:N/I:N/A:N", 0.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ],
)
def test_known_scores(vector: str, score: float) -> None:
    assert score_vector(vector).score == score


def _reference_vectors() -> list[tuple[str, float]]:
    lines = (FIXTURES / "cvss4_reference.txt").read_text().splitlines()
    return [
        (vector, float(score))
        for vector, score in (line.split() for line in lines if not line.startswith("#"))
    ]


@pytest.mark.parametrize(("vector", "score"), _reference_vectors())
def test_v4_matches_the_reference_calculator(vector: str, score: float) -> None:
    assert score_vector(vector).score == score


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV:N/AC:L/Au:N/C:P/I:P",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z",
    ],
)
def test_invalid_vectors(vector: str) -> None:
    with pytest.raises(InvalidVectorError):
        score_vector(vector)


@pytest.mark.parametrize(
    ("score", "version", "severity"),
    [
        (0.0, 3, Severity.NONE),
        (0.1, 3, Severity.LOW),
        (3.9, 4, Severity.LOW),
        (4.0, 3, Severity.MEDIUM),
        (6.9, 3, Severity.MEDIUM),
        (7.0, 4, Severity.HIGH),
        (8.9, 3, Severity.HIGH),
        (9.0, 3, Severity.CRITICAL),
        (0.0, 2, Severity.LOW),
        (4.0, 2, Severity.MEDIUM),
        (10.0, 2, Severity.HIGH),  # v2 has no "critical"
    ],
)
def test_severity_for_score(score: float, version: int, severity: Severity) -> None:
    assert severity_for_score(score, version) is severity
