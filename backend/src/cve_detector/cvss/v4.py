"""CVSS v4.0 score, ported from the FIRST reference calculator (cvss_score.js).

The algorithm, including its quirks (NaN for missing MacroVectors, first matching max
vector), is kept as in the reference so that scores match it exactly. See ``_v4_data``
for the copyright notice of the original work.
"""

import math
from collections.abc import Callable

from cve_detector.cvss._v4_data import (
    LOOKUP,
    MAX_COMPOSED,
    MAX_COMPOSED_EQ3,
    MAX_SEVERITY,
    MAX_SEVERITY_EQ3EQ6,
)
from cve_detector.cvss.base import InvalidVectorError

PREFIX = "CVSS:4.0/"

# Valid values of each metric (metrics.js), "X" meaning "not defined".
_METRICS: dict[str, tuple[str, ...]] = {
    # Base
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
    # Threat
    "E": ("X", "A", "P", "U"),
    # Environmental
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
    # Supplemental
    "S": ("X", "N", "P"),
    "AU": ("X", "N", "Y"),
    "R": ("X", "A", "U", "I"),
    "V": ("X", "D", "C"),
    "RE": ("X", "L", "M", "H"),
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

# Severity level of each value, used to measure the distance from the max vectors.
_LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
_STEP = 0.1


def parse(vector: str) -> dict[str, str]:
    if not vector.startswith(PREFIX):
        raise InvalidVectorError(f"not a CVSS v4.0 vector: {vector!r}")
    selected = dict.fromkeys(_METRICS, "X")
    seen: set[str] = set()
    for part in vector.removeprefix(PREFIX).split("/"):
        metric, _, value = part.partition(":")
        if metric not in _METRICS or value not in _METRICS[metric] or metric in seen:
            raise InvalidVectorError(f"invalid CVSS v4.0 metric {part!r} in {vector!r}")
        seen.add(metric)
        selected[metric] = value
    if missing := [m for m in _BASE if m not in seen]:
        raise InvalidVectorError(f"missing CVSS v4.0 base metrics {missing} in {vector!r}")
    return selected


def score(vector: str) -> float:
    selected = parse(vector)

    def m(metric: str) -> str:
        value = selected[metric]
        if metric == "E" and value == "X":
            return "A"  # worst case
        if metric in ("CR", "IR", "AR") and value == "X":
            return "H"  # worst case
        modified = selected.get("M" + metric, "X")
        return modified if modified != "X" else value

    if all(m(metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _macro_vector(m)
    value = LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    def lookup(*levels: int) -> float:
        return LOOKUP.get("".join(map(str, levels)), math.nan)

    score_eq1_next = lookup(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    score_eq2_next = lookup(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 0 and eq6 == 0:
        # Two paths (00 -> 01, 00 -> 10): take the higher score, NaN-aware as in JS.
        left = lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        score_eq3eq6_next = left if left > right else right
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6_next = lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq6 == 1 and eq3 in (0, 1):
        score_eq3eq6_next = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    else:
        score_eq3eq6_next = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    score_eq4_next = lookup(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    score_eq5_next = lookup(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    max_vectors = [
        a + b + c + d + e
        for a in MAX_COMPOSED["eq1"][macro[0]]
        for b in MAX_COMPOSED["eq2"][macro[1]]
        for c in MAX_COMPOSED_EQ3[macro[2]][macro[5]]
        for d in MAX_COMPOSED["eq4"][macro[3]]
        for e in MAX_COMPOSED["eq5"][macro[4]]
    ]
    distance: dict[str, float] = {}
    for max_vector in max_vectors:
        max_values = dict(p.split(":") for p in max_vector.rstrip("/").split("/"))
        distance = {
            metric: levels[m(metric)] - levels[max_values[metric]]
            for metric, levels in _LEVELS.items()
        }
        if all(d >= 0 for d in distance.values()):
            break  # the first max vector at or above the scored vector is enough

    d = distance
    current_eq1 = d["AV"] + d["PR"] + d["UI"]
    current_eq2 = d["AC"] + d["AT"]
    current_eq3eq6 = d["VC"] + d["VI"] + d["VA"] + d["CR"] + d["IR"] + d["AR"]
    current_eq4 = d["SC"] + d["SI"] + d["SA"]

    max_severity_eq1 = MAX_SEVERITY["eq1"][macro[0]] * _STEP
    max_severity_eq2 = MAX_SEVERITY["eq2"][macro[1]] * _STEP
    max_severity_eq3eq6 = MAX_SEVERITY_EQ3EQ6[macro[2]][macro[5]] * _STEP
    max_severity_eq4 = MAX_SEVERITY["eq4"][macro[3]] * _STEP

    normalized: list[float] = []
    for available, current, depth in (
        (value - score_eq1_next, current_eq1, max_severity_eq1),
        (value - score_eq2_next, current_eq2, max_severity_eq2),
        (value - score_eq3eq6_next, current_eq3eq6, max_severity_eq3eq6),
        (value - score_eq4_next, current_eq4, max_severity_eq4),
    ):
        if not math.isnan(available):
            normalized.append(available * (current / depth))
    if not math.isnan(value - score_eq5_next):
        normalized.append(0.0)  # EQ5 never moves the score within its MacroVector

    mean_distance = sum(normalized) / len(normalized) if normalized else 0.0
    value = min(max(value - mean_distance, 0.0), 10.0)
    return math.floor(value * 10 + 0.5) / 10  # JavaScript Math.round


def _macro_vector(m: Callable[[str], str]) -> str:
    av, pr, ui = m("AV"), m("PR"), m("UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2

    eq2 = 0 if m("AC") == "L" and m("AT") == "N" else 1

    vc, vi, va = m("VC"), m("VI"), m("VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif "H" in (vc, vi, va):
        eq3 = 1
    else:
        eq3 = 2

    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif "H" in (m("SC"), m("SI"), m("SA")):
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]

    worst_case = (
        (m("CR") == "H" and vc == "H")
        or (m("IR") == "H" and vi == "H")
        or (m("AR") == "H" and va == "H")
    )
    eq6 = 0 if worst_case else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"
