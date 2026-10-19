from univers.versions import SemverVersion

from cve_detector.ecosystems.intervals import Interval, covers, intersects, union


def v(text: str) -> SemverVersion:
    return SemverVersion(text)


def test_empty_intervals() -> None:
    assert Interval(v("2.0.0"), v("1.0.0")).is_empty()
    assert Interval(v("1.0.0"), v("1.0.0")).is_empty()  # [1.0.0, 1.0.0)
    assert not Interval.point(v("1.0.0")).is_empty()
    assert not Interval().is_empty()


def test_contains() -> None:
    interval = Interval(v("1.0.0"), v("2.0.0"), lower_inclusive=False, upper_inclusive=True)
    assert not interval.contains(v("1.0.0"))
    assert interval.contains(v("1.5.0"))
    assert interval.contains(v("2.0.0"))
    assert not interval.contains(v("2.0.1"))
    assert Interval().contains(v("99.0.0"))


def test_union_merges_overlapping_and_adjacent() -> None:
    merged = union(
        [
            Interval(v("3.0.0"), v("4.0.0")),
            Interval(v("1.0.0"), v("2.0.0")),
            Interval(v("2.0.0"), v("2.5.0")),  # adjacent: [1, 2) + [2, 2.5)
            Interval(v("5.0.0"), v("6.0.0"), lower_inclusive=False),
            Interval(v("4.0.0"), v("4.0.0")),  # empty, dropped
        ]
    )
    assert merged == [
        Interval(v("1.0.0"), v("2.5.0")),
        Interval(v("3.0.0"), v("4.0.0")),
        Interval(v("5.0.0"), v("6.0.0"), lower_inclusive=False),
    ]


def test_union_does_not_merge_a_gap_of_one_point() -> None:
    # [1, 2) and (2, 3) leave 2.0.0 out.
    merged = union([Interval(v("1.0.0"), v("2.0.0")), Interval(v("2.0.0"), v("3.0.0"), False)])
    assert len(merged) == 2


def test_union_with_unbounded_intervals() -> None:
    assert union([Interval(upper=v("1.0.0")), Interval(v("0.5.0"))]) == [Interval()]


def test_intersects() -> None:
    a = Interval(v("1.0.0"), v("2.0.0"))
    assert intersects(a, Interval(v("1.9.9"), None))
    assert not intersects(a, Interval(v("2.0.0"), None))
    assert intersects(a, Interval(upper=v("1.0.0"), upper_inclusive=True))
    assert not intersects(a, Interval(upper=v("1.0.0")))


def test_covers() -> None:
    container = [Interval(v("1.0.0"), v("2.0.0")), Interval(v("2.0.0"), v("3.0.0"))]
    assert covers(container, Interval(v("1.5.0"), v("2.5.0")))
    assert covers(container, Interval.point(v("1.0.0")))
    assert not covers(container, Interval(v("1.5.0"), v("3.0.0"), upper_inclusive=True))
    assert not covers(container, Interval(v("0.5.0"), v("1.5.0")))
    assert not covers(container, Interval(v("1.5.0"), None))
    assert covers([Interval()], Interval(None, None))
    assert not covers([Interval(v("1.0.0"))], Interval(upper=v("2.0.0")))
