"""Compare software versions the way NVD and vendors write them.

Python's own version tools reject strings like "4.7p1" or "5.0.51a", which are
everywhere in server software. Here a version is split into numbers and words:

  "4.7p1"   -> 4, 7, p, 1      newer than 4.7: a letter after a number is a patch
  "5.0.51a" -> 5, 0, 51, a     newer than 5.0.51
  "2.0rc1"  -> 2, 0, rc, 1     older than 2.0: rc, beta, alpha... come before a release
  "1.0a"    -> 1, 0, a         older than 1.0.1: a patch letter is less than a new number

A missing number counts as 0, so 2.0 and 2.0.0 are the same version.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

# Words that mean "before the release", from earliest to latest.
_PRE_RELEASE = {
    "dev": 0,
    "snapshot": 0,
    "alpha": 1,
    "beta": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
}
_PARTS = re.compile(r"\d+|[a-z]+")

# Each part becomes (kind, value). Kinds sort: pre-release < end of version <
# patch letter < number.
_PRE, _END, _LETTER, _NUMBER = 0, 1, 2, 3


def _parts(version: str) -> list[tuple[int, int | str]]:
    parts = []
    for part in _PARTS.findall(version.lower()):
        if part.isdigit():
            parts.append((_NUMBER, int(part)))
        elif part in _PRE_RELEASE:
            parts.append((_PRE, _PRE_RELEASE[part]))
        else:
            parts.append((_LETTER, part))
    return parts


def _part(parts: list, index: int, other: list) -> tuple[int, int | str]:
    """Part `index`, or what a missing part means: 0 next to a number, else the end."""
    if index < len(parts):
        return parts[index]
    return (_NUMBER, 0) if other[index][0] == _NUMBER else (_END, 0)


def compare(a: str, b: str) -> int:
    """-1 if a is older than b, 0 if they are the same version, 1 if a is newer."""
    left, right = _parts(a), _parts(b)
    for index in range(max(len(left), len(right))):
        x, y = _part(left, index, right), _part(right, index, left)
        if x != y:
            if x[0] != y[0]:
                return -1 if x[0] < y[0] else 1
            return -1 if x[1] < y[1] else 1
    return 0


sort_key = cmp_to_key(compare)  # sorted(versions, key=sort_key) puts them in release order


def in_range(
    version: str,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """Whether `version` is inside an NVD version range. Missing limits are open."""
    if start_including and compare(version, start_including) < 0:
        return False
    if start_excluding and compare(version, start_excluding) <= 0:
        return False
    if end_including and compare(version, end_including) > 0:
        return False
    if end_excluding and compare(version, end_excluding) >= 0:
        return False
    return True
