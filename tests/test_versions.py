import pytest

from dingdongditch.versions import compare, in_range, sort_key


@pytest.mark.parametrize(
    "older, newer",
    [
        ("2.2.8", "2.2.15"),  # numbers, not text: 8 < 15
        ("4.7", "4.7p1"),  # OpenSSH portable patch
        ("4.7p1", "4.8"),
        ("4.7p1", "4.7p2"),
        ("5.0.51", "5.0.51a"),  # MySQL letter release
        ("5.0.51a", "5.0.51b"),
        ("1.0a", "1.0.1"),  # OpenSSL: a patch letter is less than a new number
        ("2.0rc1", "2.0"),
        ("2.0beta2", "2.0rc1"),
        ("2.0alpha", "2.0beta"),
        ("2.0-dev", "2.0alpha1"),
        ("1.9.9", "2.0rc1"),
        ("3.2.8", "3.2.8.1"),  # UnrealIRCd
        ("9.4.2", "9.4.2-P1"),  # BIND patch release
        ("9.4.2-P1", "9.4.3"),
        ("1:2.3", "1:2.4"),
    ],
)
def test_release_order(older, newer):
    assert compare(older, newer) == -1
    assert compare(newer, older) == 1


@pytest.mark.parametrize(
    "a, b",
    [("2.0", "2.0.0"), ("8.3", "8.3.0"), ("1.0RC1", "1.0rc1"), ("2.3.4", "2.3.4"), ("1_2", "1.2")],
)
def test_same_version(a, b):
    assert compare(a, b) == 0
    assert compare(b, a) == 0


def test_versions_sort_in_release_order():
    shuffled = ["2.0", "1.10", "2.0rc1", "1.9", "2.0.1", "1.10a", "2.0beta"]
    assert sorted(shuffled, key=sort_key) == [
        "1.9", "1.10", "1.10a", "2.0beta", "2.0rc1", "2.0", "2.0.1"
    ]


@pytest.mark.parametrize(
    "version, limits, inside",
    [
        ("2.2.8", {"end_excluding": "2.2.15"}, True),
        ("2.2.15", {"end_excluding": "2.2.15"}, False),
        ("2.2.15", {"end_including": "2.2.15"}, True),
        ("2.2.16", {"end_including": "2.2.15"}, False),
        ("2.0.0", {"start_including": "2.0", "end_excluding": "2.2"}, True),
        ("2.0", {"start_excluding": "2.0", "end_excluding": "2.2"}, False),
        ("1.9", {"start_including": "2.0"}, False),
        ("4.7p1", {"start_including": "4.0", "end_excluding": "4.7p2"}, True),
        ("4.7p1", {}, True),  # no limits: every version
    ],
)
def test_nvd_ranges(version, limits, inside):
    assert in_range(version, **limits) is inside
