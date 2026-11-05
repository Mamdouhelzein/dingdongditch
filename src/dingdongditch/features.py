"""Turn CVE records into numbers a model can learn from, as they were on a cutoff date.

"As of a cutoff" means: only CVEs NVD had published before that day, and only the
exploits Exploit-DB had published before it. The CISA KEV date is kept in its own
column, so the caller decides which CVEs count as exploited: listed before the
cutoff for training, listed after it for testing.

NVD has no history, so CVSS, CWE, description and products are today's copies.
They change little once a CVE is analysed. References are left out on purpose:
news stories and "Exploit" links pile up after a CVE is attacked, so they would
leak the answer into the question.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import date

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

NUMBER_INPUTS = [
    "cvss3_score",
    "cvss2_score",
    "exploits",
    "exploit_verified",
    "exploit_remote",
    "exploit_webapps",
    "exploit_local",
    "age_days",
]
NUMBER_NAMES = [
    "cvss3_score",
    "no_cvss3",
    "cvss2_score",
    "no_cvss2",
    "log_exploits",
    "exploit_verified",
    "exploit_remote",
    "exploit_webapps",
    "exploit_local",
    "log_age_days",
]


def load(con: sqlite3.Connection, cutoff: date) -> pd.DataFrame:
    """One row per CVE published before the cutoff (rejected CVEs left out)."""
    day = cutoff.isoformat()
    frame = pd.read_sql_query(
        """
        SELECT c.id, c.published, c.description, c.cvss3_score, c.cvss3_vector,
               c.cvss2_score, c.cvss2_vector, c.cwes, k.date_added AS kev_added
        FROM cve c LEFT JOIN kev k ON k.cve_id = c.id
        WHERE c.published < ? AND c.status != 'Rejected'
        ORDER BY c.id
        """,
        con,
        params=(day,),
    )

    products = defaultdict(set)
    for cve_id, vendor, product in con.execute(
        "SELECT DISTINCT cve_id, vendor, product FROM cve_cpe"
    ):
        products[cve_id].update((vendor, f"{vendor}:{product}"))
    frame["products"] = [" ".join(sorted(products.get(cve_id, ()))) for cve_id in frame["id"]]

    exploits = pd.read_sql_query(
        """
        SELECT cve_id AS id, COUNT(*) AS exploits, MAX(verified) AS exploit_verified,
               MAX(type = 'remote') AS exploit_remote, MAX(type = 'webapps') AS exploit_webapps,
               MAX(type = 'local') AS exploit_local
        FROM exploitdb WHERE published < ? GROUP BY cve_id
        """,
        con,
        params=(day,),
    )
    frame = frame.merge(exploits, on="id", how="left")
    columns = ["exploits", "exploit_verified", "exploit_remote", "exploit_webapps", "exploit_local"]
    frame[columns] = frame[columns].fillna(0).astype(int)

    published = pd.to_datetime(frame["published"].str[:10])
    frame["age_days"] = (pd.Timestamp(cutoff) - published).dt.days
    return frame


def kev_between(frame: pd.DataFrame, start: date | None, end: date | None) -> np.ndarray:
    """True for CVEs CISA listed on or after `start` and before `end` (None = no limit)."""
    added = frame["kev_added"].fillna("")
    listed = added != ""
    if start is not None:
        listed &= added >= start.isoformat()
    if end is not None:
        listed &= added < end.isoformat()
    return listed.to_numpy(dtype=bool)


def _numbers(frame: pd.DataFrame) -> np.ndarray:
    return np.column_stack(
        [
            frame["cvss3_score"].fillna(0),
            frame["cvss3_score"].isna(),
            frame["cvss2_score"].fillna(0),
            frame["cvss2_score"].isna(),
            np.log1p(frame["exploits"]),
            frame["exploit_verified"],
            frame["exploit_remote"],
            frame["exploit_webapps"],
            frame["exploit_local"],
            np.log1p(frame["age_days"].clip(lower=0)),
        ]
    ).astype(float)


def _number_names(transformer, input_features) -> list[str]:
    return NUMBER_NAMES


def _cvss_parts(vectors: pd.Series) -> list[dict[str, str]]:
    """'CVSS:3.1/AV:N/AC:L/...' -> {'AV': 'N', 'AC': 'L', ...} for each CVE."""
    parts = []
    for vector in vectors:
        found = {}
        if isinstance(vector, str):
            for item in vector.split("/"):
                key, sep, value = item.partition(":")
                if sep and key != "CVSS":
                    found[key] = value
        parts.append(found)
    return parts


def make_vectorizer(min_count: int = 5) -> ColumnTransformer:
    """Turns load()'s table into a sparse matrix. Fit it on the training CVEs only.

    Words, weakness types and products seen in fewer than `min_count` CVEs are
    dropped: they are too rare to learn from.
    """
    tokens = {"tokenizer": str.split, "token_pattern": None, "lowercase": False, "binary": True}
    return ColumnTransformer(
        [
            (
                "number",
                make_pipeline(
                    FunctionTransformer(_numbers, feature_names_out=_number_names),
                    StandardScaler(),
                ),
                NUMBER_INPUTS,
            ),
            (
                "cvss3",
                make_pipeline(
                    FunctionTransformer(_cvss_parts, feature_names_out="one-to-one"),
                    DictVectorizer(),
                ),
                "cvss3_vector",
            ),
            (
                "cvss2",
                make_pipeline(
                    FunctionTransformer(_cvss_parts, feature_names_out="one-to-one"),
                    DictVectorizer(),
                ),
                "cvss2_vector",
            ),
            ("cwe", CountVectorizer(min_df=min_count, **tokens), "cwes"),
            ("product", CountVectorizer(min_df=min_count, **tokens), "products"),
            (
                "text",
                TfidfVectorizer(
                    min_df=min_count,
                    max_features=30_000,
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    stop_words="english",
                    dtype=np.float32,
                ),
                "description",
            ),
        ],
        sparse_threshold=1.0,
    )
