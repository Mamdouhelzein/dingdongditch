"""Train the model that ranks CVEs by how likely CISA is to list them as exploited.

The model learns from what was known on a cutoff date: CVEs already on CISA's KEV
list count as exploited, everything else as not (yet). Its settings are chosen by
standing one year earlier and checking which setting best found the CVEs listed in
the year up to the cutoff, so the year after the cutoff is never looked at until
the final test.
"""

from __future__ import annotations

import importlib.util
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from dingdongditch.evaluate import (
    HORIZON,
    EvaluationError,
    cvss_scores,
    epss_scores,
    exploit_scores,
    make_test_set,
    measure,
)
from dingdongditch.features import kev_between, load, make_vectorizer

# Logistic regression adds up clues. C: how closely it may fit the training CVEs
# (small = simpler); class_weight="balanced" makes the few exploited CVEs count as
# much as all the others.
LOGISTIC = [
    {"kind": "logistic", "C": C, "class_weight": weight}
    for C in (0.03, 0.1, 0.3, 1.0)
    for weight in ("balanced", None)
]
# XGBoost builds 400 small decision trees, so it can learn combinations of clues.
# max_depth: how many clues one tree can combine; scale_pos_weight: how much more an
# exploited CVE counts than the others. Each takes 4-10 minutes on the full data.
XGBOOST = [
    {"kind": "xgboost", "max_depth": depth, "scale_pos_weight": weight}
    for depth in (3, 6)
    for weight in (1, 20)
]
GRID = LOGISTIC + XGBOOST

# The best of each kind in choose_settings() standing on 2024-05-01, judged on the
# year after. XGBoost won that check (average precision 0.087 against 0.042), but on
# the two years it wasn't chosen on they tied: XGBoost ahead from 2025-05-01 (0.063
# against 0.057), logistic regression ahead from 2023-05-01 (0.020 against 0.014).
# On a tie the simpler model wins: it trains ten times faster, and each clue's
# weight can be read straight off it to explain a score.
# After CVSS became one v3-or-v2 set of features, the same check picked C=0.3 again,
# and logistic regression scored 0.060 (2025) and 0.022 (2023). XGBoost's figures
# above are from before that change.
DEFAULT = {"kind": "logistic", "C": 0.3, "class_weight": None}
XGBOOST_BEST = {"kind": "xgboost", "max_depth": 6, "scale_pos_weight": 20}

MODEL_FILE = "model.joblib"  # saved next to the database


class MissingXGBoost(ImportError):
    """XGBoost is an optional extra, and it isn't installed."""

    def __init__(self) -> None:
        super().__init__(
            "XGBoost isn't installed. Add it with `pipx inject dingdongditch xgboost`, "
            "or `pip install \"dingdongditch[xgboost]\"`."
        )


def xgboost_installed() -> bool:
    return importlib.util.find_spec("xgboost") is not None


def _classifier(settings: dict):
    options = dict(settings)
    kind = options.pop("kind")
    if kind == "logistic":
        return LogisticRegression(solver="liblinear", max_iter=1000, **options)
    if kind == "xgboost":
        if not xgboost_installed():
            raise MissingXGBoost
        from xgboost import XGBClassifier  # optional, and slow to import

        return XGBClassifier(
            n_estimators=400,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.5,
            tree_method="hist",
            n_jobs=-1,
            random_state=0,
            **options,
        )
    raise ValueError(f"Unknown kind of model: {kind!r}")


def _labels(frame: pd.DataFrame, cutoff: date) -> np.ndarray:
    labels = kev_between(frame, None, cutoff)
    if not labels.any():
        raise EvaluationError(f"No CVE was on CISA's KEV list before {cutoff.isoformat()}")
    return labels


def fit(frame: pd.DataFrame, cutoff: date, settings: dict, min_count: int = 5) -> Pipeline:
    """Train on load()'s table for `cutoff`: KEV before the cutoff means exploited."""
    model = Pipeline(
        [("features", make_vectorizer(min_count)), ("classifier", _classifier(settings))]
    )
    return model.fit(frame, _labels(frame, cutoff))


def scores(model: Pipeline, frame: pd.DataFrame) -> np.ndarray:
    """Higher means more likely to be exploited. Only the order matters."""
    return model.predict_proba(frame)[:, 1]


@dataclass(frozen=True)
class Choice:
    settings: dict
    tried: list[tuple[dict, dict[str, float]]]  # every setting and its measures


def choose_settings(
    frame: pd.DataFrame,
    cutoff: date,
    grid: list[dict] = GRID,
    min_count: int = 5,
    report: Callable[[dict, dict[str, float]], None] = lambda settings, measures: None,
) -> Choice:
    """Try each setting standing on `cutoff`, judged on the year after it.

    Call it with a cutoff one year before the real one. The best average precision
    wins.
    """
    test = make_test_set(frame, cutoff, HORIZON)
    labels = _labels(frame, cutoff)
    matrix = make_vectorizer(min_count).fit_transform(frame)
    tried = []
    for settings in grid:
        classifier = _classifier(settings).fit(matrix, labels)
        measures = measure(classifier.predict_proba(matrix)[test.rows, 1], test.listed)
        report(settings, measures)
        tried.append((settings, measures))
    best = max(tried, key=lambda item: item[1]["average precision"])[0]
    return Choice(settings=best, tried=tried)


def score_spread(model: Pipeline, frame: pd.DataFrame) -> list[float]:
    """1,001 scores that cut every CVE's score into 1,000 equal slices.

    Saved with the model, they turn one CVE's score into "riskier than 99.3% of
    all CVEs" without scoring all 400,000 again.
    """
    return np.quantile(scores(model, frame), np.linspace(0, 1, 1001)).tolist()


def save(model: Pipeline, path: Path, info: dict) -> None:
    """Save a trained model with notes on how it was made (settings, date, counts)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, **info}, path)


def load_saved(path: Path) -> dict:
    """The saved model and its notes; the model itself is under "model"."""
    return joblib.load(path)


@dataclass(frozen=True)
class TestResult:
    cutoff: date
    judged: int  # CVEs public and not yet on CISA's list at the cutoff
    listed: int  # how many of them CISA listed in the year after
    rows: list[tuple[str, dict[str, float]]]  # each ranking and its measures
    epss_missing: bool  # no EPSS scores were saved for the cutoff day


def time_travel_test(
    con: sqlite3.Connection, cutoff: date, settings: dict, today: date
) -> TestResult:
    """Train on what was known on `cutoff`, then judge every ranking on the year after."""
    if cutoff + HORIZON > today:
        raise EvaluationError(
            f"The year after {cutoff.isoformat()} isn't over yet, so the test can't be "
            f"judged. Pick a date on or before {(today - HORIZON).isoformat()}."
        )
    frame = load(con, cutoff)
    test = make_test_set(frame, cutoff)
    if not test.listed.any():
        raise EvaluationError(
            f"CISA listed none of the CVEs public on {cutoff.isoformat()} in the year after"
        )
    rankings = {"CVSS": cvss_scores(frame), "Public exploit": exploit_scores(frame)}
    epss_missing = False
    try:
        rankings[f"EPSS on {cutoff.isoformat()}"] = epss_scores(con, frame, cutoff)
    except EvaluationError:
        epss_missing = True
    rankings["Our model"] = scores(fit(frame, cutoff, settings), frame)
    rows = [(name, measure(ranking[test.rows], test.listed)) for name, ranking in rankings.items()]
    return TestResult(cutoff, len(test.rows), int(test.listed.sum()), rows, epss_missing)
