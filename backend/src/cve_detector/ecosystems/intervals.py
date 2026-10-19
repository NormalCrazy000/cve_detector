"""Version intervals: the common form of dependency specs and advisory affected ranges.

Versions are treated as a dense ordered set: ``[1.0, 2.0)`` contains every version from
1.0 up to, not including, 2.0, whether or not it was ever published.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from univers.versions import Version


@dataclass(frozen=True, slots=True)
class Interval:
    """``lower``/``upper`` set to ``None`` mean unbounded on that side."""

    lower: Version | None = None
    upper: Version | None = None
    lower_inclusive: bool = True
    upper_inclusive: bool = False

    @classmethod
    def point(cls, version: Version) -> "Interval":
        return cls(version, version, lower_inclusive=True, upper_inclusive=True)

    def is_empty(self) -> bool:
        if self.lower is None or self.upper is None:
            return False
        if self.lower == self.upper:
            return not (self.lower_inclusive and self.upper_inclusive)
        return bool(self.lower > self.upper)

    def contains(self, version: Version) -> bool:
        if self.lower is not None and (
            version < self.lower or (version == self.lower and not self.lower_inclusive)
        ):
            return False
        return self.upper is None or not (
            version > self.upper or (version == self.upper and not self.upper_inclusive)
        )


def intersection(a: Interval, b: Interval) -> Interval:
    lower, lower_inclusive = _max_lower(a, b)
    upper, upper_inclusive = _min_upper(a, b)
    return Interval(lower, upper, lower_inclusive, upper_inclusive)


def intersects(a: Interval, b: Interval) -> bool:
    return not intersection(a, b).is_empty()


def union(intervals: Iterable[Interval]) -> list[Interval]:
    """Sorted, non-overlapping intervals covering the same versions."""
    pending = sorted((i for i in intervals if not i.is_empty()), key=_lower_sort_key)
    merged: list[Interval] = []
    for interval in pending:
        if merged and _touches(merged[-1], interval):
            last = merged[-1]
            upper, upper_inclusive = _max_upper(last, interval)
            merged[-1] = Interval(last.lower, upper, last.lower_inclusive, upper_inclusive)
        else:
            merged.append(interval)
    return merged


def covers(container: list[Interval], interval: Interval) -> bool:
    """True when ``interval`` lies entirely inside ``union(container)``."""
    for candidate in union(container):
        lower_ok = candidate.lower is None or (
            interval.lower is not None
            and (
                candidate.lower < interval.lower
                or (
                    candidate.lower == interval.lower
                    and (candidate.lower_inclusive or not interval.lower_inclusive)
                )
            )
        )
        upper_ok = candidate.upper is None or (
            interval.upper is not None
            and (
                candidate.upper > interval.upper
                or (
                    candidate.upper == interval.upper
                    and (candidate.upper_inclusive or not interval.upper_inclusive)
                )
            )
        )
        if lower_ok and upper_ok:
            return True
    return False


def _lower_sort_key(interval: Interval) -> tuple[int, Version | None, int]:
    if interval.lower is None:
        return (0, None, 0)
    return (1, interval.lower, 0 if interval.lower_inclusive else 1)


def _touches(left: Interval, right: Interval) -> bool:
    """``left`` starts before ``right``; true if they overlap or are adjacent."""
    if left.upper is None or right.lower is None:
        return True
    if left.upper == right.lower:
        return left.upper_inclusive or right.lower_inclusive
    return bool(left.upper > right.lower)


def _max_lower(a: Interval, b: Interval) -> tuple[Version | None, bool]:
    if a.lower is None:
        return b.lower, b.lower_inclusive
    if b.lower is None or a.lower > b.lower:
        return a.lower, a.lower_inclusive
    if a.lower == b.lower:
        return a.lower, a.lower_inclusive and b.lower_inclusive
    return b.lower, b.lower_inclusive


def _min_upper(a: Interval, b: Interval) -> tuple[Version | None, bool]:
    if a.upper is None:
        return b.upper, b.upper_inclusive
    if b.upper is None or a.upper < b.upper:
        return a.upper, a.upper_inclusive
    if a.upper == b.upper:
        return a.upper, a.upper_inclusive and b.upper_inclusive
    return b.upper, b.upper_inclusive


def _max_upper(a: Interval, b: Interval) -> tuple[Version | None, bool]:
    if a.upper is None or b.upper is None:
        return None, False
    if a.upper > b.upper:
        return a.upper, a.upper_inclusive
    if a.upper == b.upper:
        return a.upper, a.upper_inclusive or b.upper_inclusive
    return b.upper, b.upper_inclusive
