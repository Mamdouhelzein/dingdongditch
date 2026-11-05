"""Train the model that ranks CVEs by how likely CISA is to list them as exploited.

The model learns from what was known on a cutoff date: CVEs already on CISA's KEV
list count as exploited, everything else as not (yet). Its settings are chosen by
standing one year earlier and checking which setting best found the CVEs listed in
the year up to the cutoff, so the year after the cutoff is never looked at until
the final test.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from dingdongditch.evaluate import HORIZON, EvaluationError, make_test_set, measure
from dingdongditch.features import kev_between, make_vectorizer

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

# The winner of choose_settings() standing on 2024-05-01, judged on the year after:
# average precision 0.087, against 0.042 for the best logistic regression.
BEST = {"kind": "xgboost", "max_depth": 6, "scale_pos_weight": 20}


def _classifier(settings: dict) -> LogisticRegression | XGBClassifier:
    options = dict(settings)
    kind = options.pop("kind")
    if kind == "logistic":
        return LogisticRegression(solver="liblinear", max_iter=1000, **options)
    if kind == "xgboost":
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
