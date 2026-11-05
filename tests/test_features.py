"""Model features, built from a small handmade database."""

import pickle
from datetime import date

import numpy as np
import pytest

from dingdongditch import db, features

CUTOFF = date(2025, 5, 1)
V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2 = "AV:L/AC:H/Au:N/C:P/I:N/A:N"


@pytest.fixture
def con():
    connection = db.connect(":memory:")
    cves = [
        # id, published, status, description, cvss3, vector3, cvss2, vector2, cwes
        ("CVE-A", "2020-01-02T10:00:00.000", "Analyzed",
         "Remote code execution in the FTP server", 9.8, V3, None, None, "CWE-78"),
        ("CVE-B", "2024-06-01T00:00:00.000", "Modified",
         "Local information disclosure in the kernel", None, None, 1.9, V2, "CWE-200 CWE-78"),
        ("CVE-C", "2025-06-01T00:00:00.000", "Analyzed",
         "Published after the cutoff", 5.0, V3, None, None, ""),
        ("CVE-D", "2023-01-01T00:00:00.000", "Rejected",
         "** REJECT ** Not a vulnerability", None, None, None, None, ""),
        ("CVE-E", "2025-04-30T23:59:59.000", "Received",
         "Cross-site scripting in the admin panel of the FTP server", None, None, None, None,
         ""),
    ]
    connection.executemany(
        "INSERT INTO cve (id, published, last_modified, status, description, cvss3_score, "
        "cvss3_vector, cvss2_score, cvss2_vector, cwes) VALUES (?, ?, 'm', ?, ?, ?, ?, ?, ?, ?)",
        cves,
    )
    connection.executemany(
        "INSERT INTO cve_cpe (cve_id, part, vendor, product, cpe) VALUES (?, 'a', ?, ?, 'x')",
        [("CVE-A", "vsftpd_project", "vsftpd"), ("CVE-A", "vsftpd_project", "vsftpd"),
         ("CVE-B", "linux", "linux_kernel"), ("CVE-E", "acme", "admin"),
         ("CVE-E", "linux", "linux_kernel")],
    )
    connection.executemany(
        "INSERT INTO kev VALUES (?, 'v', 'p', 'n', ?, 'Unknown')",
        [("CVE-A", "2021-11-03"), ("CVE-B", "2025-07-01")],
    )
    connection.executemany(
        "INSERT INTO exploitdb VALUES (?, ?, ?, ?, 'unix', ?)",
        [
            (1, "CVE-A", "2011-07-05", "remote", 1),
            (2, "CVE-A", "2012-01-01", "webapps", 0),
            (3, "CVE-B", "2025-06-01", "local", 1),  # after the cutoff: not known yet
        ],
    )
    yield connection
    connection.close()


def test_load_keeps_only_what_was_known_at_the_cutoff(con):
    frame = features.load(con, CUTOFF)
    assert list(frame["id"]) == ["CVE-A", "CVE-B", "CVE-E"]
    a, b, e = (frame.iloc[i] for i in range(3))
    assert (a["exploits"], a["exploit_verified"], a["exploit_remote"], a["exploit_webapps"]) == (
        2, 1, 1, 1
    )
    assert (b["exploits"], b["exploit_local"]) == (0, 0)
    assert a["products"] == "vsftpd_project vsftpd_project:vsftpd"
    assert e["products"] == "acme acme:admin linux linux:linux_kernel"
    assert a["age_days"] == (CUTOFF - date(2020, 1, 2)).days
    assert e["age_days"] == 1


def test_kev_between_splits_before_and_after(con):
    frame = features.load(con, CUTOFF)
    assert list(features.kev_between(frame, None, CUTOFF)) == [True, False, False]
    assert list(features.kev_between(frame, CUTOFF, None)) == [False, True, False]
    assert list(features.kev_between(frame, CUTOFF, date(2025, 7, 1))) == [False, False, False]


def test_cvss_vectors_become_parts():
    parts = features._cvss_parts([V3, V2, None])
    assert parts[0]["AV"] == "N" and "CVSS" not in parts[0]
    assert parts[1] == {"AV": "L", "AC": "H", "Au": "N", "C": "P", "I": "N", "A": "N"}
    assert parts[2] == {}


def test_vectorizer_names_every_column(con):
    frame = features.load(con, CUTOFF)
    vectorizer = features.make_vectorizer(min_count=1)
    matrix = vectorizer.fit_transform(frame)
    names = list(vectorizer.get_feature_names_out())
    assert matrix.shape == (3, len(names))
    for name in [
        "number__log_exploits",
        "number__no_cvss3",
        "cvss3__AV=N",
        "cvss2__Au=N",
        "cwe__CWE-78",
        "product__linux:linux_kernel",
        "text__remote code",
    ]:
        assert name in names, name
    row = dict(zip(names, matrix.toarray()[0], strict=True))
    assert row["cvss3__AV=N"] == 1
    assert row["cwe__CWE-200"] == 0
    assert row["product__vsftpd_project"] == 1


def test_rare_words_and_products_are_dropped(con):
    frame = features.load(con, CUTOFF)
    vectorizer = features.make_vectorizer(min_count=2)
    vectorizer.fit(frame)
    names = set(vectorizer.get_feature_names_out())
    assert "cwe__CWE-78" in names  # two CVEs have it
    assert "cwe__CWE-200" not in names  # only one does
    assert {n for n in names if n.startswith("product__")} == {
        "product__linux", "product__linux:linux_kernel"
    }
    assert "text__ftp server" in names
    assert "text__kernel" not in names


def test_fitted_vectorizer_can_be_saved_and_reused(con):
    frame = features.load(con, CUTOFF)
    vectorizer = features.make_vectorizer(min_count=1).fit(frame)
    again = pickle.loads(pickle.dumps(vectorizer))
    first = vectorizer.transform(frame).toarray()
    assert np.allclose(first, again.transform(frame).toarray())
