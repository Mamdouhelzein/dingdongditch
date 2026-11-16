"""Training on a small made-up world where one word gives the exploited CVEs away."""

import pickle
from datetime import date

import numpy as np
import pandas as pd
import pytest

from dingdongditch import evaluate, train

CUTOFF = date(2025, 5, 1)
YEAR_EARLIER = date(2024, 5, 1)


def make_frame(size: int = 400, seed: int = 0) -> pd.DataFrame:
    """CVEs whose description says 'gateway' get exploited; the rest don't."""
    rng = np.random.default_rng(seed)
    risky = rng.random(size) < 0.1
    kev_added = []
    for is_risky in risky:
        roll = rng.random()
        if not is_risky or roll < 0.3:
            kev_added.append(None)
        elif roll < 0.6:
            kev_added.append("2023-06-01")  # known before both cutoffs
        elif roll < 0.8:
            kev_added.append("2024-09-01")  # listed in the year before the cutoff
        else:
            kev_added.append("2025-09-01")  # listed in the year after it
    words = ["printer", "editor", "library", "plugin"]
    return pd.DataFrame(
        {
            "id": [f"CVE-{i}" for i in range(size)],
            "description": [
                ("remote gateway " if r else "") + rng.choice(words) + " bug" for r in risky
            ],
            "cvss3_score": rng.uniform(1, 10, size),
            "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss2_score": 7.5,
            "cvss2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "cwes": "CWE-79",
            "products": "acme acme:thing",
            "kev_added": kev_added,
            "exploits": 0,
            "exploit_verified": 0,
            "exploit_remote": 0,
            "exploit_webapps": 0,
            "exploit_local": 0,
            "age_days": rng.integers(1, 3000, size),
        }
    )


def test_model_learns_the_giveaway_word():
    frame = make_frame()
    model = train.fit(
        frame, CUTOFF, {"kind": "logistic", "C": 1.0, "class_weight": "balanced"}, min_count=1
    )
    test = evaluate.make_test_set(frame, CUTOFF)
    assert test.listed.any()
    measures = evaluate.measure(train.scores(model, frame)[test.rows], test.listed)
    assert measures["top 10%"] == 1.0


def test_choose_settings_tries_the_whole_grid_and_picks_the_best():
    frame = make_frame()
    seen = []
    choice = train.choose_settings(
        frame, YEAR_EARLIER, min_count=1, report=lambda s, m: seen.append(s)
    )
    assert seen == train.GRID
    assert [settings for settings, _ in choice.tried] == train.GRID
    best = max(measures["average precision"] for _, measures in choice.tried)
    assert any(
        settings == choice.settings and measures["average precision"] == best
        for settings, measures in choice.tried
    )


def test_nothing_on_the_list_yet_is_refused():
    frame = make_frame()
    with pytest.raises(evaluate.EvaluationError, match="before 2020-01-01"):
        train.fit(frame, date(2020, 1, 1), train.GRID[0], min_count=1)


def test_trained_model_can_be_saved_and_reused():
    frame = make_frame()
    model = train.fit(frame, CUTOFF, train.GRID[0], min_count=1)
    again = pickle.loads(pickle.dumps(model))
    assert np.allclose(train.scores(model, frame), train.scores(again, frame))


@pytest.mark.parametrize("settings", [train.DEFAULT, train.XGBOOST[0], train.XGBOOST_BEST])
def test_every_kind_of_model_learns_the_giveaway_word(settings):
    frame = make_frame()
    model = train.fit(frame, CUTOFF, settings, min_count=1)
    test = evaluate.make_test_set(frame, CUTOFF)
    measures = evaluate.measure(train.scores(model, frame)[test.rows], test.listed)
    assert measures["top 10%"] == 1.0


def test_chosen_settings_are_in_the_grid():
    assert train.DEFAULT in train.GRID
    assert train.XGBOOST_BEST in train.GRID


def test_unknown_kind_is_refused():
    with pytest.raises(ValueError, match="Unknown kind"):
        train.fit(make_frame(), CUTOFF, {"kind": "magic"}, min_count=1)


def test_xgboost_is_only_needed_for_xgboost(monkeypatch):
    monkeypatch.setattr(train, "xgboost_installed", lambda: False)
    train._classifier(train.DEFAULT)  # logistic regression still works
    with pytest.raises(train.MissingXGBoost, match=r"dingdongditch\[xgboost\]"):
        train._classifier(train.XGBOOST_BEST)


class FakeCon:
    """time_travel_test only hands its connection on to load() and epss_scores()."""


@pytest.fixture
def world(monkeypatch):
    monkeypatch.setattr(train, "load", lambda con, cutoff: make_frame())
    monkeypatch.setattr(
        train, "epss_scores",
        lambda con, frame, day: np.random.default_rng(1).random(len(frame)),
    )


def test_time_travel_test_judges_every_ranking_with_intervals(world):
    result = train.time_travel_test(FakeCon(), CUTOFF, train.DEFAULT, date(2026, 11, 1))
    judged = result.everything
    assert [name for name, _ in judged.rows] == ["CVSS", "Public exploit", "EPSS", "Our model"]
    assert judged.listed == int(evaluate.make_test_set(make_frame(), CUTOFF).listed.sum())
    assert dict(judged.rows)["Our model"]["top 10%"] == 1.0
    assert judged.intervals["Our model"]["top 10%"] == (1.0, 1.0)
    assert set(judged.against_epss) == {"top 1%", "top 5%", "top 10%"}
    assert (result.settings, result.tuned, result.epss_missing) == (train.DEFAULT, False, False)
    # No description in this world says "exploited", so the check changes nothing.
    assert result.said_exploited == 0
    assert result.without_those.listed == judged.listed


def test_tuning_chooses_on_the_year_before_only(world, monkeypatch):
    seen = []
    real = train.choose_settings

    def spy(frame, cutoff, grid, **more):
        seen.append((cutoff, grid))
        return real(frame, cutoff, grid, min_count=1)

    monkeypatch.setattr(train, "choose_settings", spy)
    result = train.time_travel_test(
        FakeCon(), CUTOFF, train.DEFAULT, date(2026, 11, 1), tune=train.LOGISTIC
    )
    assert seen == [(YEAR_EARLIER, train.LOGISTIC)]
    assert result.tuned and result.settings in train.LOGISTIC


def test_tuning_falls_back_when_the_list_is_too_young(world):
    # A year before 2024-05-01 nothing in this world was on CISA's list yet.
    result = train.time_travel_test(
        FakeCon(), YEAR_EARLIER, train.DEFAULT, date(2026, 11, 1), tune=train.LOGISTIC
    )
    assert (result.tuned, result.settings) == (False, train.DEFAULT)


def test_giveaway_check_drops_cves_that_say_they_were_exploited(monkeypatch):
    frame = make_frame()
    later = frame["kev_added"] == "2025-09-01"
    first = frame.index[later][0]
    frame.loc[first, "description"] += ", exploited in the wild"
    monkeypatch.setattr(train, "load", lambda con, cutoff: frame)
    monkeypatch.setattr(
        train, "epss_scores", lambda con, frame, day: np.zeros(len(frame))
    )
    result = train.time_travel_test(FakeCon(), CUTOFF, train.DEFAULT, date(2026, 11, 1))
    assert result.said_exploited == 1
    assert result.without_those.listed == result.everything.listed - 1
    assert result.without_those.judged == result.everything.judged - 1


def test_test_days_are_only_added_up_when_their_years_dont_overlap(world):
    today = date(2026, 11, 1)
    first = train.time_travel_test(FakeCon(), YEAR_EARLIER, train.DEFAULT, today)
    second = train.time_travel_test(FakeCon(), CUTOFF, train.DEFAULT, today)
    everything, strict = train.pooled([second, first])
    assert everything.listed == first.everything.listed + second.everything.listed
    assert strict.listed == everything.listed
    assert train.pooled([first]) is None
    close = train.time_travel_test(FakeCon(), date(2025, 1, 1), train.DEFAULT, today)
    assert train.pooled([close, second]) is None  # January and May 2025 share months
