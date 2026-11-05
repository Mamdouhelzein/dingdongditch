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

from dingdongditch.evaluate import HORIZON, EvaluationError, make_test_set, measure
from dingdongditch.features import kev_between, make_vectorizer

# C: how closely the model may fit the training CVEs (small = simpler model).
# class_weight="balanced" makes the few exploited CVEs count as much as all the others.
GRID = [
    {"C": C, "class_weight": weight}
    for C in (0.03, 0.1, 0.3, 1.0)
    for weight in ("balanced", None)
]


def _classifier(settings: dict) -> LogisticRegression:
    return LogisticRegression(solver="liblinear", max_iter=1000, **settings)


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
    return model.decision_function(frame)


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
        measures = measure(classifier.decision_function(matrix)[test.rows], test.listed)
        report(settings, measures)
        tried.append((settings, measures))
    best = max(tried, key=lambda item: item[1]["average precision"])[0]
    return Choice(settings=best, tried=tried)
