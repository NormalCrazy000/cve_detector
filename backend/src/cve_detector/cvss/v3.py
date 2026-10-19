"""CVSS v3.0 and v3.1 base score (FIRST specification, section 7)."""

import math

from cve_detector.cvss.base import InvalidVectorError

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # scope unchanged
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},  # only validated
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
# Temporal and environmental metrics: accepted, not used by the base score.
_OTHER = frozenset(
    {"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
)


def score(vector: str) -> float:
    version, metrics = _parse(vector)
    w = {metric: _WEIGHTS[metric][metrics[metric]] for metric in _WEIGHTS}
    changed = metrics["S"] == "C"

    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        privileges = _PR_SCOPE_CHANGED[metrics["PR"]]
    else:
        impact = 6.42 * iss
        privileges = w["PR"]
    exploitability = 8.22 * w["AV"] * w["AC"] * privileges * w["UI"]

    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    roundup = _roundup_v31 if version == "3.1" else _roundup_v30
    return roundup(min(total, 10.0))


def _parse(vector: str) -> tuple[str, dict[str, str]]:
    prefix, _, body = vector.partition("/")
    if prefix not in ("CVSS:3.0", "CVSS:3.1"):
        raise InvalidVectorError(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        metric, _, value = part.partition(":")
        known = metric in _OTHER or value in _WEIGHTS.get(metric, {})
        if not known or metric in metrics:
            raise InvalidVectorError(f"invalid CVSS v3 metric {part!r} in {vector!r}")
        metrics[metric] = value
    if missing := [m for m in _WEIGHTS if m not in metrics]:
        raise InvalidVectorError(f"missing CVSS v3 base metrics {missing} in {vector!r}")
    return prefix.removeprefix("CVSS:"), metrics


def _roundup_v30(value: float) -> float:
    return math.ceil(value * 10) / 10


def _roundup_v31(value: float) -> float:
    """Round up to one decimal, avoiding floating point artifacts (spec appendix A)."""
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000
    return (as_int // 10_000 + 1) / 10
