"""The matcher's answer-key check, against a small handmade NVD."""

import json
from pathlib import Path

import pytest

from dingdongditch import db, lab_check

TRUTH = Path(__file__).parent.parent / "data" / "lab_truth.json"


def cpe(product, version="*"):
    return f"cpe:2.3:a:samba:{product}:{version}:*:*:*:*:*:*:*"


ROWS = [
    # cve, cpe, start_including, end_excluding
    ("CVE-2007-0001", cpe("samba", "3.0.20"), None, None),  # names the release
    ("CVE-2007-0002", cpe("samba"), "3.0.0", "3.0.25"),  # a range that starts
    ("CVE-2020-0003", cpe("samba"), None, "4.10.18"),  # no first release
    ("CVE-2009-0004", cpe("samba"), None, "3.2.0"),  # no first release either
    ("CVE-2021-0005", cpe("samba"), "4.0.0", "4.13.0"),  # a newer branch only
]


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "vulns.db"
    con = db.connect(path)
    with con:
        con.executemany(
            "INSERT INTO cve (id, published, last_modified, status, description) "
            "VALUES (?, 'p', 'm', 'Analyzed', 'd')",
            [(row[0],) for row in ROWS],
        )
        con.executemany(
            "INSERT INTO cve_cpe (cve_id, part, vendor, product, cpe, "
            "version_start_including, version_end_excluding) "
            "VALUES (?, 'a', 'samba', 'samba', ?, ?, ?)",
            ROWS,
        )
    con.close()
    return path


def write(tmp_path, **lists):
    path = tmp_path / "truth.json"
    path.write_text(json.dumps({"services": [
        {"lab": "Lab", "product": "Samba 3.0.20", "cpe": "cpe:/a:samba:samba:3.0.20", **lists}
    ]}))
    return path


def test_check_sorts_known_cves_into_found_possible_missed_and_wrong(database, tmp_path):
    truth = write(
        tmp_path,
        affected={"CVE-2007-0001": "x", "CVE-2009-0004": "x", "CVE-2021-0005": "x"},
        not_sure={"CVE-2020-0003": "x", "CVE-2007-0002": "x"},
    )
    con = db.connect(database)
    [result] = lab_check.check(con, lab_check.load_truth(truth))
    con.close()
    assert result.found == ["CVE-2007-0001"]
    assert result.possible == ["CVE-2009-0004"]  # true, but NVD names no first release
    assert result.missed == ["CVE-2021-0005"]
    assert result.wrong == ["CVE-2007-0002"]  # the key says not sure; the matcher says sure
    assert (result.sure_matches, result.possible_matches, result.unlabelled) == (2, 2, 0)
    totals = lab_check.summary([result])
    assert (totals["known"], totals["found"], totals["missed"], totals["wrong"]) == (3, 1, 1, 1)
    words = lab_check.report([result])
    assert "Recall: 1 of 3 known CVEs reported as sure (33%)" in words
    assert "1 only as possible, 1 missed." in words
    assert "MISSED: CVE-2021-0005" in words and "WRONGLY SURE: CVE-2007-0002" in words


def test_command_passes_only_when_nothing_is_missed_or_wrong(database, tmp_path, capsys):
    good = write(tmp_path, affected={"CVE-2007-0001": "x"}, not_sure={"CVE-2020-0003": "x"})
    assert lab_check.main([str(good), "--db", str(database)]) == 0
    out = capsys.readouterr().out
    assert "Recall: 1 of 1 known CVEs reported as sure (100%)" in out
    assert "1 of the 2 sure matches aren't in the answer key" in out
    bad = write(tmp_path, affected={"CVE-2021-0005": "x"})
    assert lab_check.main([str(bad), "--db", str(database)]) == 1


def test_command_says_what_is_missing(tmp_path, database, capsys):
    assert lab_check.main([str(tmp_path / "truth.json"), "--db", str(tmp_path / "no.db")]) == 1
    assert "update-db" in capsys.readouterr().out
    assert lab_check.main([str(tmp_path / "none.json"), "--db", str(database)]) == 1
    assert "Can't read the answer key" in capsys.readouterr().out


@pytest.mark.parametrize(
    "service, complaint",
    [
        ({"cpe": "samba 3.0.20"}, "isn't cpe:/a:vendor:product:version"),
        ({"cpe": "cpe:/a:samba:samba"}, "isn't cpe:/a:vendor:product:version"),  # no version
        ({"affected": {"Zerologon": "x"}}, "isn't a CVE id"),
        ({"affected": {"CVE-2020-0003": "x"}, "not_sure": {"CVE-2020-0003": "x"}}, "both lists"),
    ],
)
def test_bad_answer_keys_are_refused(tmp_path, service, complaint):
    path = tmp_path / "truth.json"
    entry = {"lab": "Lab", "product": "Samba", "cpe": "cpe:/a:samba:samba:3.0.20", **service}
    path.write_text(json.dumps({"services": [entry]}))
    with pytest.raises(lab_check.TruthError, match=complaint):
        lab_check.load_truth(path)


def test_the_repositorys_answer_key_is_usable():
    entries = lab_check.load_truth(TRUTH)
    assert len(entries) >= 5
    assert all(entry.affected for entry in entries)
    samba = next(e for e in entries if "Samba" in e.product)
    assert "CVE-2020-1472" in samba.not_sure  # Zerologon, the match that started this
