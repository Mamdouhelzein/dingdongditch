"""The ranking measures and the baselines our model has to beat."""

from datetime import date

import numpy as np
import pandas as pd
import pytest

from dingdongditch import db, evaluate

CUTOFF = date(2025, 5, 1)


def test_perfect_ranking_catches_everything_in_its_top():
    scores = np.arange(100, 0, -1)
    listed = np.zeros(100, dtype=bool)
    listed[[0, 1]] = True
    assert evaluate.caught_in_top(scores, listed, 0.01) == 0.5  # top 1 of 100
    assert evaluate.caught_in_top(scores, listed, 0.05) == 1.0
    assert evaluate.average_precision(scores, listed) == 1.0


def test_worst_ranking_catches_nothing():
    scores = np.arange(100)
    listed = np.zeros(100, dtype=bool)
    listed[[0, 1]] = True
    assert evaluate.caught_in_top(scores, listed, 0.10) == 0.0


def test_ties_at_the_edge_count_as_a_random_order():
    # 10 CVEs all scored 9.8, one of them listed. The top 10% is one CVE out of 10
    # tied ones, so on average it catches 1/10 of the listed CVE.
    scores = np.full(10, 9.8)
    listed = np.zeros(10, dtype=bool)
    listed[3] = True
    assert evaluate.caught_in_top(scores, listed, 0.10) == pytest.approx(0.1)
    # Above the tie everything counts in full: the 9.9 one is first, alone.
    scores = np.array([9.9, 5, 5, 5, 5, 5, 5, 5, 5, 5])
    listed = np.array([True, False, False, False, False, False, False, False, False, True])
    assert evaluate.caught_in_top(scores, listed, 0.10) == 0.5
    assert evaluate.caught_in_top(scores, listed, 0.20) == pytest.approx(0.5 + 0.5 / 9)


def test_nothing_listed_is_refused():
    with pytest.raises(evaluate.EvaluationError):
        evaluate.caught_in_top(np.ones(5), np.zeros(5, dtype=bool), 0.5)


def test_measure_reports_every_share():
    scores = np.arange(200, 0, -1)
    listed = np.zeros(200, dtype=bool)
    listed[0] = True
    assert evaluate.measure(scores, listed) == {
        "top 1%": 1.0,
        "top 5%": 1.0,
        "top 10%": 1.0,
        "average precision": 1.0,
    }


def make_frame():
    return pd.DataFrame(
        {
            "id": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
            "kev_added": ["2024-01-01", "2025-08-01", None, "2026-08-01"],
            "cvss3_score": [9.8, None, None, 5.0],
            "cvss2_score": [None, 7.5, None, None],
            "exploits": [3, 0, 1, 0],
        }
    )


def test_test_set_drops_cves_already_listed_and_marks_the_next_year():
    test = evaluate.make_test_set(make_frame(), CUTOFF)
    assert list(test.rows) == [1, 2, 3]
    assert list(test.listed) == [True, False, False]  # CVE-4 was listed too late


def test_cvss_falls_back_to_v2_then_zero():
    assert list(evaluate.cvss_scores(make_frame())) == [9.8, 7.5, 0.0, 5.0]


def test_public_exploit_baseline():
    assert list(evaluate.exploit_scores(make_frame())) == [1.0, 0.0, 1.0, 0.0]


def test_epss_baseline_uses_the_cutoff_day():
    con = db.connect(":memory:")
    con.executemany(
        "INSERT INTO epss_history VALUES (?, ?, ?, 0.5)",
        [("2025-05-01", "CVE-2", 0.3), ("2025-05-01", "CVE-4", 0.01), ("2026-01-01", "CVE-3", 0.9)],
    )
    scores = evaluate.baselines(con, make_frame(), CUTOFF)
    assert list(scores) == ["CVSS", "Public exploit", "EPSS on 2025-05-01"]
    assert list(scores["EPSS on 2025-05-01"]) == [0.0, 0.3, 0.0, 0.01]
    with pytest.raises(evaluate.EvaluationError, match="--epss-date 2024-05-01"):
        evaluate.epss_scores(con, make_frame(), date(2024, 5, 1))
    con.close()
