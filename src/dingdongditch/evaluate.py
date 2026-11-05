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
"""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from datetime import date, timedelta

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from dingdongditch.features import kev_between

SHARES = (0.01, 0.05, 0.10)
HORIZON = timedelta(days=365)


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


def caught_in_top(scores: np.ndarray, listed: np.ndarray, share: float) -> float:
    """Share of the listed CVEs found in the top `share` of the ranking.

    Many CVEs have the same score (thousands have CVSS 9.8), so CVEs tied at the
    edge of the top are counted as if their order were random: the expected value.
    """
    scores = np.asarray(scores, dtype=float)
    listed = np.asarray(listed, dtype=bool)
    if not listed.any():
        raise EvaluationError("No CVE in the test set was listed, so nothing can be caught")
    top = math.ceil(share * len(scores))
    if top == 0:
        return 0.0
    edge = np.sort(scores)[::-1][top - 1]
    above = scores > edge
    tied = scores == edge
    room = top - above.sum()
    caught = listed[above].sum() + listed[tied].sum() * room / tied.sum()
    return float(caught / listed.sum())


def average_precision(scores: np.ndarray, listed: np.ndarray) -> float:
    return float(average_precision_score(np.asarray(listed, dtype=bool), scores))


def measure(scores: np.ndarray, listed: np.ndarray) -> dict[str, float]:
    """Every measure for one ranking."""
    results = {f"top {share:.0%}": caught_in_top(scores, listed, share) for share in SHARES}
    results["average precision"] = average_precision(scores, listed)
    return results


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
