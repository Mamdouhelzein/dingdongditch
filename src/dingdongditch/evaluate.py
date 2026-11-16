"""How well a ranking of CVEs predicts which ones CISA lists as exploited next.

The test is a time-travel one. Stand on a cutoff date, rank every CVE that was
public and not yet on CISA's KEV list, then look at which of them CISA listed in
the following year. A good ranking puts those near the top.

The measures:
  caught in top X%  if you fixed the top X% of the ranking, what share of the CVEs
                    CISA went on to list would you have fixed
  average precision one number for the whole ranking: 1.0 is perfect, and picking
                    at random scores about the share of CVEs that got listed

Baselines: CVSS (what most teams sort by), "has a public exploit", and EPSS as it
was on the cutoff day (today's EPSS already knows what happened next).

How sure the numbers are. A test year has few listed CVEs (91 and 53 in the first
two tests), so every measure comes with a 95% interval from a bootstrap: the listed
CVEs are redrawn 2,000 times, each time as many as there were, with repeats. The
other CVEs, 200,000 or more, stay as they are, because they only fix where the top
of a ranking ends and that barely moves. Two rankings are compared CVE by CVE on
the same listed CVEs: the interval of the gap between them, and a sign test on the
CVEs only one of them caught.

The giveaway check. NVD keeps no history, so a description read today may say
"exploited in the wild" because someone added it after the attack. judge() can be
run again without every CVE whose description says so.
"""

from __future__ import annotations

import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import date, timedelta

import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.metrics import average_precision_score

from dingdongditch.features import kev_between

SHARES = (0.01, 0.05, 0.10)
HORIZON = timedelta(days=365)
RESAMPLES = 2000  # bootstrap redraws behind every interval
INTERVAL = (0.025, 0.975)  # a 95% interval
MODEL, EPSS = "Our model", "EPSS"  # the two rankings that are compared CVE by CVE

# Words in a description that give away that the CVE was attacked.
_SAYS_EXPLOITED = re.compile(
    r"exploit(?:ed|ation) in the wild|exploits? exists? in the wild|actively exploited"
    r"|being exploited|(?:was|were|has been|have been) exploited"
    r"|aware of (?:a report|reports)",
    re.IGNORECASE,
)


class EvaluationError(Exception):
    """The data needed for an evaluation is missing."""


@dataclass(frozen=True)
class TestSet:
    """The CVEs a ranking is judged on, and which of them CISA listed next."""

    rows: np.ndarray  # positions in load()'s table: public, and not on KEV at the cutoff
    listed: np.ndarray  # for each of those rows: listed during the horizon


def make_test_set(frame: pd.DataFrame, cutoff: date, horizon: timedelta = HORIZON) -> TestSet:
    already = kev_between(frame, None, cutoff)
    later = kev_between(frame, cutoff, cutoff + horizon)
    rows = np.flatnonzero(~already)
    return TestSet(rows=rows, listed=later[rows])


def says_exploited(frame: pd.DataFrame) -> np.ndarray:
    """True for CVEs whose description (today's copy) says they were attacked."""
    return frame["description"].str.contains(_SAYS_EXPLOITED, na=False).to_numpy(dtype=bool)


def without(test: TestSet, drop: np.ndarray) -> TestSet:
    """The test set minus the CVEs marked in `drop` (one mark per row of load()'s table)."""
    keep = ~np.asarray(drop, dtype=bool)[test.rows]
    return TestSet(rows=test.rows[keep], listed=test.listed[keep])


def caught_each(scores: np.ndarray, listed: np.ndarray, share: float) -> np.ndarray:
    """For each listed CVE: 1 if it is in the top `share` of the ranking, else 0.

    Many CVEs have the same score (thousands have CVSS 9.8), so CVEs tied at the
    edge of the top are counted as if their order were random: each gets the
    chance that it lands inside.
    """
    scores = np.asarray(scores, dtype=float)
    listed = np.asarray(listed, dtype=bool)
    if not listed.any():
        raise EvaluationError("No CVE in the test set was listed, so nothing can be caught")
    top = math.ceil(share * len(scores))
    if top == 0:
        return np.zeros(int(listed.sum()))
    edge = np.sort(scores)[::-1][top - 1]
    above = scores > edge
    tied = scores == edge
    room = top - above.sum()
    return np.where(above, 1.0, np.where(tied, room / tied.sum(), 0.0))[listed]


def caught_in_top(scores: np.ndarray, listed: np.ndarray, share: float) -> float:
    """Share of the listed CVEs found in the top `share` of the ranking."""
    caught = caught_each(scores, listed, share)
    return float(caught.sum() / len(caught))


def average_precision(scores: np.ndarray, listed: np.ndarray) -> float:
    return float(average_precision_score(np.asarray(listed, dtype=bool), scores))


def measure(scores: np.ndarray, listed: np.ndarray) -> dict[str, float]:
    """Every measure for one ranking."""
    results = {f"top {share:.0%}": caught_in_top(scores, listed, share) for share in SHARES}
    results["average precision"] = average_precision(scores, listed)
    return results


def redraws(listed: int, seed: int = 0) -> np.ndarray:
    """RESAMPLES bootstrap redraws of `listed` CVEs: how often each one was picked.

    The same redraws are used for every ranking of a test, so two rankings are
    always compared on the same redrawn CVEs.
    """
    rng = np.random.default_rng(seed)
    return rng.multinomial(listed, np.full(listed, 1 / listed), size=RESAMPLES)


def interval(each: np.ndarray, picks: np.ndarray) -> tuple[float, float]:
    """95% interval for the average of one number per listed CVE."""
    low, high = np.quantile(picks @ each / picks.sum(axis=1), INTERVAL)
    return float(low), float(high)


def average_precision_interval(
    scores: np.ndarray, listed: np.ndarray, picks: np.ndarray
) -> tuple[float, float]:
    """95% interval for average precision, redrawing only the listed CVEs.

    Average precision adds up, over each score a listed CVE has, the share of
    listed CVEs with that score times the precision down to it. A redraw changes
    how often each listed CVE counts, so both are worked out again from the counts.
    """
    scores = np.asarray(scores, dtype=float)
    listed = np.asarray(listed, dtype=bool)
    order = np.argsort(-scores[listed], kind="stable")
    ours = scores[listed][order]
    others = np.sort(scores[~listed])
    starts = np.flatnonzero(np.r_[True, ours[1:] != ours[:-1]])  # one group per score
    others_above = len(others) - np.searchsorted(others, ours[starts], side="left")
    counts = np.add.reduceat(picks[:, order], starts, axis=1)
    found = counts.cumsum(axis=1)
    precision = found / np.maximum(found + others_above, 1)
    low, high = np.quantile((counts * precision).sum(axis=1) / picks.sum(axis=1), INTERVAL)
    return float(low), float(high)


@dataclass(frozen=True)
class Gap:
    """Two rankings compared on the same listed CVEs, at one cut-off like "top 1%"."""

    difference: float  # share the first caught minus share the second caught
    low: float  # the 95% interval of that difference
    high: float
    only_first: int  # listed CVEs only the first ranking caught
    only_second: int
    p_value: float  # sign test: the chance of a split this lopsided between equals

    @property
    def beyond_chance(self) -> bool:
        return self.low > 0 and self.p_value < 0.05


def gap(first: np.ndarray, second: np.ndarray, picks: np.ndarray) -> Gap:
    """Compare two rankings from caught_each(), CVE by CVE."""
    low, high = interval(first - second, picks)
    a, b = first >= 0.5, second >= 0.5  # a CVE tied at the edge counts if it's likelier in
    only_first, only_second = int((a & ~b).sum()), int((b & ~a).sum())
    differ = only_first + only_second
    return Gap(
        difference=float((first - second).mean()),
        low=low,
        high=high,
        only_first=only_first,
        only_second=only_second,
        p_value=float(binomtest(only_first, differ).pvalue) if differ else 1.0,
    )


@dataclass(frozen=True)
class Judged:
    """Every ranking judged on one set of CVEs."""

    judged: int  # CVEs in the set
    listed: int  # how many of them CISA listed in the year after
    rows: list[tuple[str, dict[str, float]]]  # each ranking and its measures
    intervals: dict[str, dict[str, tuple[float, float]]]  # ranking -> measure -> interval
    caught: dict[str, dict[str, np.ndarray]]  # ranking -> "top 1%" -> caught_each()
    against_epss: dict[str, Gap]  # "top 1%" -> our model against EPSS; {} without both


def _gaps(caught: dict[str, dict[str, np.ndarray]], picks: np.ndarray) -> dict[str, Gap]:
    if MODEL not in caught or EPSS not in caught:
        return {}
    return {key: gap(caught[MODEL][key], caught[EPSS][key], picks) for key in caught[MODEL]}


def judge(rankings: dict[str, np.ndarray], test: TestSet, seed: int = 0) -> Judged:
    """Measure each ranking (one score per row of load()'s table) on a test set."""
    if not test.listed.any():
        raise EvaluationError("No CVE in the test set was listed, so nothing can be caught")
    picks = redraws(int(test.listed.sum()), seed)
    rows, intervals, caught = [], {}, {}
    for name, ranking in rankings.items():
        scores = np.asarray(ranking, dtype=float)[test.rows]
        rows.append((name, measure(scores, test.listed)))
        caught[name] = {
            f"top {share:.0%}": caught_each(scores, test.listed, share) for share in SHARES
        }
        intervals[name] = {key: interval(each, picks) for key, each in caught[name].items()}
        intervals[name]["average precision"] = average_precision_interval(
            scores, test.listed, picks
        )
    return Judged(
        len(test.rows), int(test.listed.sum()), rows, intervals, caught, _gaps(caught, picks)
    )


def pool(parts: list[Judged], seed: int = 0) -> Judged:
    """Several test years as one: every listed CVE of every year, each in its own year.

    Only for years that don't overlap, so no CVE is counted twice. A ranking missing
    from any year is left out, and average precision isn't pooled: it belongs to one
    ranking of one set of CVEs.
    """
    names = [name for name, _ in parts[0].rows if all(name in p.caught for p in parts)]
    caught = {
        name: {
            key: np.concatenate([p.caught[name][key] for p in parts])
            for key in parts[0].caught[name]
        }
        for name in names
    }
    listed = sum(p.listed for p in parts)
    picks = redraws(listed, seed)
    rows = [(name, {key: float(each.mean()) for key, each in caught[name].items()})
            for name in names]
    intervals = {
        name: {key: interval(each, picks) for key, each in caught[name].items()}
        for name in names
    }
    return Judged(
        sum(p.judged for p in parts), listed, rows, intervals, caught, _gaps(caught, picks)
    )


def cvss_scores(frame: pd.DataFrame) -> np.ndarray:
    """CVSS v3 base score, or v2 for older CVEs, or 0 when NVD hasn't scored it."""
    return frame["cvss3_score"].fillna(frame["cvss2_score"]).fillna(0).to_numpy(dtype=float)


def exploit_scores(frame: pd.DataFrame) -> np.ndarray:
    """1 if Exploit-DB had a public exploit before the cutoff, else 0."""
    return (frame["exploits"] > 0).to_numpy(dtype=float)


def epss_scores(con: sqlite3.Connection, frame: pd.DataFrame, day: date) -> np.ndarray:
    """EPSS as it was on `day`, or 0 for CVEs it didn't score."""
    saved = dict(
        con.execute("SELECT cve_id, score FROM epss_history WHERE date = ?", (day.isoformat(),))
    )
    if not saved:
        raise EvaluationError(
            f"No EPSS scores saved for {day.isoformat()}. "
            f"Run `dingdongditch update-db --epss-date {day.isoformat()}` first."
        )
    return np.array([saved.get(cve_id, 0.0) for cve_id in frame["id"]], dtype=float)


def baselines(con: sqlite3.Connection, frame: pd.DataFrame, cutoff: date) -> dict[str, np.ndarray]:
    """The rankings our model has to beat, for every CVE in load()'s table."""
    return {
        "CVSS": cvss_scores(frame),
        "Public exploit": exploit_scores(frame),
        f"EPSS on {cutoff.isoformat()}": epss_scores(con, frame, cutoff),
    }
