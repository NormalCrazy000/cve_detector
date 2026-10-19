"""CVSS v2 base score (FIRST specification, section 3.2.1)."""

import math

from cve_detector.cvss.base import InvalidVectorError

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}
# Temporal and environmental metrics: accepted, not used by the base score.
_OTHER = frozenset({"E", "RL", "RC", "CDP", "TD", "CR", "IR", "AR"})


def score(vector: str) -> float:
    metrics = _parse(vector)
    w = {metric: _WEIGHTS[metric][metrics[metric]] for metric in _WEIGHTS}
    impact = 10.41 * (1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"]))
    exploitability = 20 * w["AV"] * w["AC"] * w["Au"]
    factor = 0.0 if impact == 0 else 1.176
    base = (0.6 * impact + 0.4 * exploitability - 1.5) * factor
    return max(math.floor(base * 10 + 0.5) / 10, 0.0)


def _parse(vector: str) -> dict[str, str]:
    body = vector.strip().removeprefix("(").removesuffix(")").removeprefix("CVSS:2.0/")
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        metric, _, value = part.partition(":")
        known = metric in _OTHER or value in _WEIGHTS.get(metric, {})
        if not known or metric in metrics:
            raise InvalidVectorError(f"invalid CVSS v2 metric {part!r} in {vector!r}")
        metrics[metric] = value
    if missing := [m for m in _WEIGHTS if m not in metrics]:
        raise InvalidVectorError(f"missing CVSS v2 base metrics {missing} in {vector!r}")
    return metrics
