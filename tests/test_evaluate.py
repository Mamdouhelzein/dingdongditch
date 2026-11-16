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


def ranked_world(size=400, listed=30, seed=3):
    """Scores where listed CVEs tend to rank high, with plenty of ties."""
    rng = np.random.default_rng(seed)
    is_listed = np.zeros(size, dtype=bool)
    is_listed[rng.choice(size, listed, replace=False)] = True
    scores = np.round(rng.random(size) + 0.4 * is_listed, 1)  # rounded: many ties
    return scores, is_listed


def test_caught_each_adds_up_to_caught_in_top():
    scores, listed = ranked_world()
    for share in evaluate.SHARES:
        each = evaluate.caught_each(scores, listed, share)
        assert len(each) == listed.sum()
        assert ((each >= 0) & (each <= 1)).all()
        assert each.mean() == pytest.approx(evaluate.caught_in_top(scores, listed, share))


def test_interval_holds_the_measure_and_narrows_with_more_cves():
    scores, listed = ranked_world(size=400, listed=30)
    each = evaluate.caught_each(scores, listed, 0.10)
    low, high = evaluate.interval(each, evaluate.redraws(30))
    assert low <= each.mean() <= high
    assert 0.05 < high - low < 0.5  # 30 CVEs can't pin a share down

    scores, listed = ranked_world(size=40_000, listed=3000)
    each = evaluate.caught_each(scores, listed, 0.10)
    narrow_low, narrow_high = evaluate.interval(each, evaluate.redraws(3000))
    assert narrow_high - narrow_low < (high - low) / 3


def test_redraws_are_repeatable_and_keep_the_count():
    picks = evaluate.redraws(25)
    assert picks.shape == (evaluate.RESAMPLES, 25)
    assert (picks.sum(axis=1) == 25).all()
    assert (picks == evaluate.redraws(25)).all()
    assert (picks != evaluate.redraws(25, seed=1)).any()


def test_average_precision_interval_matches_sklearn_on_redrawn_cves():
    from sklearn.metrics import average_precision_score

    scores, listed = ranked_world()
    picks = evaluate.redraws(int(listed.sum()))[:50]
    positions = np.flatnonzero(listed)
    expected = []
    for counts in picks:
        weights = np.ones(len(scores))
        weights[positions] = counts  # a listed CVE picked twice counts twice, unpicked not at all
        expected.append(average_precision_score(listed, scores, sample_weight=weights))
    low, high = evaluate.average_precision_interval(scores, listed, picks)
    assert (low, high) == pytest.approx(tuple(np.quantile(expected, evaluate.INTERVAL)))
    # Counting every listed CVE once gives the plain average precision back.
    once = np.ones((1, int(listed.sum())), dtype=int)
    same, _ = evaluate.average_precision_interval(scores, listed, once)
    assert same == pytest.approx(evaluate.average_precision(scores, listed))


def test_gap_counts_the_cves_only_one_ranking_caught():
    first = np.array([1, 1, 1, 1, 1, 1, 1, 1, 0, 0.0])
    second = np.array([0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0])
    result = evaluate.gap(first, second, evaluate.redraws(10))
    assert result.difference == pytest.approx(0.6)
    assert (result.only_first, result.only_second) == (7, 1)
    assert result.p_value == pytest.approx(0.0703125)  # 2 * (1 + 8) / 2**8
    assert result.low < 0.6 < result.high
    assert not result.beyond_chance  # the interval is above 0, but p isn't under 0.05

    clear = evaluate.gap(np.ones(12), np.zeros(12), evaluate.redraws(12))
    assert (clear.only_first, clear.p_value < 0.001, clear.beyond_chance) == (12, True, True)

    same = evaluate.gap(first, first, evaluate.redraws(10))
    assert (same.difference, same.low, same.high, same.p_value) == (0, 0, 0, 1)
    assert not same.beyond_chance


def test_a_gap_of_four_cves_can_never_be_beyond_chance():
    # The README's top 1% from May 2025: 29 against 25 of 91. Even if the 4 extra CVEs
    # were the only ones the two rankings disagreed on, a sign test gives p = 0.125.
    first = np.r_[np.ones(29), np.zeros(62)]
    second = np.r_[np.ones(25), np.zeros(66)]
    result = evaluate.gap(first, second, evaluate.redraws(91))
    assert (result.only_first, result.only_second) == (4, 0)
    assert result.p_value == pytest.approx(0.125)
    assert not result.beyond_chance


def rankings_and_test(seed=3):
    scores, listed = ranked_world(seed=seed)
    rng = np.random.default_rng(seed)
    test = evaluate.TestSet(rows=np.arange(len(scores)), listed=listed)
    return {"CVSS": rng.random(len(scores)), evaluate.EPSS: rng.random(len(scores)),
            evaluate.MODEL: scores}, test


def test_judge_measures_every_ranking_and_compares_ours_with_epss():
    rankings, test = rankings_and_test()
    judged = evaluate.judge(rankings, test)
    assert (judged.judged, judged.listed) == (400, 30)
    assert [name for name, _ in judged.rows] == ["CVSS", evaluate.EPSS, evaluate.MODEL]
    for name, measures in judged.rows:
        assert measures == evaluate.measure(rankings[name], test.listed)
        for key, value in measures.items():
            low, high = judged.intervals[name][key]
            assert low <= value <= high
    assert set(judged.against_epss) == {"top 1%", "top 5%", "top 10%"}
    top = judged.against_epss["top 10%"]
    ours, theirs = dict(judged.rows)[evaluate.MODEL], dict(judged.rows)[evaluate.EPSS]
    assert top.difference == pytest.approx(ours["top 10%"] - theirs["top 10%"])

    del rankings[evaluate.EPSS]
    assert evaluate.judge(rankings, test).against_epss == {}


def test_judge_only_looks_at_the_test_rows():
    rankings, test = rankings_and_test()
    half = evaluate.TestSet(rows=test.rows[::2], listed=test.listed[::2])
    judged = evaluate.judge(rankings, half)
    assert (judged.judged, judged.listed) == (200, int(test.listed[::2].sum()))
    assert dict(judged.rows)["CVSS"] == evaluate.measure(rankings["CVSS"][::2], half.listed)


def test_pool_adds_test_years_up():
    years = [evaluate.judge(*rankings_and_test(seed)) for seed in (3, 4)]
    both = evaluate.pool(years)
    assert (both.judged, both.listed) == (800, 60)
    caught = [year.caught[evaluate.MODEL]["top 5%"] for year in years]
    assert dict(both.rows)[evaluate.MODEL]["top 5%"] == pytest.approx(
        np.concatenate(caught).mean()
    )
    assert "average precision" not in dict(both.rows)[evaluate.MODEL]
    assert both.against_epss["top 5%"].only_first == sum(
        year.against_epss["top 5%"].only_first for year in years
    )
    # A year without EPSS leaves EPSS, and the comparison, out of the total.
    rankings, test = rankings_and_test(5)
    del rankings[evaluate.EPSS]
    partly = evaluate.pool([*years, evaluate.judge(rankings, test)])
    assert [name for name, _ in partly.rows] == ["CVSS", evaluate.MODEL]
    assert partly.against_epss == {}


def test_giveaway_descriptions_are_spotted_and_dropped():
    frame = pd.DataFrame({"description": [
        "A buffer overflow in the parser.",
        "Use after free, as exploited in the wild in May 2012.",
        "Apple is aware of a report that this issue may have been actively exploited.",
        "An attacker could exploit this to run code.",  # could, not did
        "This vulnerability has been exploited by ransomware groups.",
    ]})
    marks = evaluate.says_exploited(frame)
    assert list(marks) == [False, True, True, False, True]
    test = evaluate.TestSet(rows=np.array([0, 1, 3, 4]),
                            listed=np.array([True, True, False, True]))
    strict = evaluate.without(test, marks)
    assert list(strict.rows) == [0, 3]
    assert list(strict.listed) == [True, False]
