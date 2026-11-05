"""The downloaders, fed by a fake session so no test touches the internet."""

import gzip
import json
from datetime import date

import pytest
import requests
from http_fakes import FakeResponse, FakeSession

from dingdongditch import collect, db


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    monkeypatch.setattr(collect, "RETRY_WAIT", 0)


@pytest.fixture
def con():
    connection = db.connect(":memory:")
    yield connection
    connection.close()


KEV = {
    "catalogVersion": "2026.11.04",
    "vulnerabilities": [
        {
            "cveID": "CVE-2011-2523",
            "vendorProject": "vsftpd",
            "product": "vsftpd",
            "vulnerabilityName": "vsftpd Backdoor",
            "dateAdded": "2026-01-01",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2007-2447",
            "vendorProject": "Samba",
            "product": "Samba",
            "vulnerabilityName": "Samba Command Injection",
            "dateAdded": "2025-06-01",
            "knownRansomwareCampaignUse": "Known",
        },
    ],
}


def kev_session(*answers):
    return FakeSession({collect.KEV_URL: list(answers)})


def test_kev_fills_the_table(con):
    count = collect.update_kev(con, kev_session(FakeResponse(body=json.dumps(KEV).encode())))
    assert count == 2
    rows = con.execute("SELECT * FROM kev ORDER BY cve_id").fetchall()
    assert rows[0] == (
        "CVE-2007-2447", "Samba", "Samba", "Samba Command Injection", "2025-06-01", "Known"
    )
    assert db.get_meta(con, "kev_version") == "2026.11.04"
    assert db.get_meta(con, "kev_updated")


def test_kev_update_replaces_old_rows(con):
    collect.update_kev(con, kev_session(FakeResponse(body=json.dumps(KEV).encode())))
    smaller = {**KEV, "vulnerabilities": KEV["vulnerabilities"][:1]}
    collect.update_kev(con, kev_session(FakeResponse(body=json.dumps(smaller).encode())))
    assert con.execute("SELECT cve_id FROM kev").fetchall() == [("CVE-2011-2523",)]


def test_busy_server_is_tried_again(con):
    session = kev_session(
        FakeResponse(503),
        requests.ConnectionError("network blip"),
        FakeResponse(body=json.dumps(KEV).encode()),
    )
    assert collect.update_kev(con, session) == 2
    assert len(session.asked) == 3


def test_missing_page_is_not_tried_again(con):
    session = kev_session(FakeResponse(404), FakeResponse(body=json.dumps(KEV).encode()))
    with pytest.raises(collect.DownloadError, match="HTTP 404"):
        collect.update_kev(con, session)
    assert len(session.asked) == 1


def test_gives_up_after_a_few_tries(con):
    session = kev_session(*[FakeResponse(503)] * collect.TRIES)
    with pytest.raises(collect.DownloadError, match="HTTP 503"):
        collect.update_kev(con, session)
    assert len(session.asked) == collect.TRIES


@pytest.mark.parametrize("body", [b"<html>maintenance</html>", b'{"vulnerabilities": [{}]}'])
def test_bad_kev_keeps_the_old_data(con, body):
    collect.update_kev(con, kev_session(FakeResponse(body=json.dumps(KEV).encode())))
    with pytest.raises(collect.DownloadError, match="KEV"):
        collect.update_kev(con, kev_session(FakeResponse(body=body)))
    assert con.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 2


EPSS_CSV = (
    "#model_version:v2026.06.15,score_date:2026-11-05T12:03:04Z\n"
    "cve,epss,percentile\n"
    "CVE-1999-0001,0.04753,0.91915\n"
    "CVE-2011-2523,0.94012,0.99920\n"
)


def epss_session(*answers):
    return FakeSession({collect.EPSS_URL: list(answers)})


def test_epss_reads_the_notes_and_scores():
    notes, rows = collect.parse_epss(EPSS_CSV)
    assert notes == {"model_version": "v2026.06.15", "score_date": "2026-11-05T12:03:04Z"}
    assert rows == [("CVE-1999-0001", 0.04753, 0.91915), ("CVE-2011-2523", 0.94012, 0.9992)]


def test_epss_without_notes_line_still_works():
    notes, rows = collect.parse_epss(EPSS_CSV.split("\n", 1)[1])
    assert notes == {}
    assert len(rows) == 2


@pytest.mark.parametrize(
    "text",
    [
        "cve,score\nCVE-1-1,0.1\n",
        "cve,epss,percentile\nCVE-1-1,high,0.5\n",
        "cve,epss,percentile\nX\n",
    ],
)
def test_epss_in_another_format_is_refused(text):
    with pytest.raises(collect.DownloadError, match="EPSS"):
        collect.parse_epss(text)


def test_epss_gzipped_download_fills_the_table(con):
    body = gzip.compress(EPSS_CSV.encode())
    assert collect.update_epss(con, epss_session(FakeResponse(body=body))) == 2
    assert con.execute("SELECT score FROM epss WHERE cve_id = 'CVE-2011-2523'").fetchone() == (
        0.94012,
    )
    assert db.get_meta(con, "epss_model") == "v2026.06.15"
    assert db.get_meta(con, "epss_date") == "2026-11-05T12:03:04Z"


def test_epss_already_unzipped_download_also_works(con):
    assert collect.update_epss(con, epss_session(FakeResponse(body=EPSS_CSV.encode()))) == 2


def test_damaged_epss_download_keeps_the_old_data(con):
    collect.update_epss(con, epss_session(FakeResponse(body=gzip.compress(EPSS_CSV.encode()))))
    broken = gzip.compress(EPSS_CSV.encode())[:-20]
    with pytest.raises(collect.DownloadError, match="damaged"):
        collect.update_epss(con, epss_session(FakeResponse(body=broken)))
    assert con.execute("SELECT COUNT(*) FROM epss").fetchone()[0] == 2


EDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,date_updated,"
    "verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    '17491,exploits/unix/remote/17491.rb,"vsftpd 2.3.4 - Backdoor Command Execution",'
    "2011-07-05,Metasploit,remote,unix,,2011-07-05,2011-07-05,1,CVE-2011-2523;OSVDB-73573,,,,,\n"
    '16320,exploits/unix/remote/16320.rb,"Samba ""username map script"", with a\nnewline",'
    "2010-05-17,Metasploit,remote,unix,,2010-05-17,2010-05-17,0,"
    "CVE-2007-2447;cve-2007-2447,,,,,\n"
    '1,exploits/x/1.txt,"No CVE at all",2000-01-01,x,dos,linux,,2000-01-01,2000-01-01,1,'
    "OSVDB-1;CVE-n/a,,,,,\n"
    '2,exploits/x/2.txt,"Typo in the CVE",2015-01-01,x,local,linux,,2015-01-01,2015-01-01,1,'
    '"CVE-2015- 5698;CVE-2019\ufffd9193",,,,,\n'
)


def test_exploitdb_keeps_one_row_per_exploit_and_cve():
    rows = sorted(collect.parse_exploitdb(EDB_CSV))
    assert rows == [
        (2, "CVE-2015-5698", "2015-01-01", "local", "linux", 1),
        (2, "CVE-2019-9193", "2015-01-01", "local", "linux", 1),
        (16320, "CVE-2007-2447", "2010-05-17", "remote", "unix", 0),
        (17491, "CVE-2011-2523", "2011-07-05", "remote", "unix", 1),
    ]


def test_exploitdb_in_another_format_is_refused():
    with pytest.raises(collect.DownloadError, match="Exploit-DB"):
        collect.parse_exploitdb("id,name\n1,x\n")
    with pytest.raises(collect.DownloadError, match="Exploit-DB"):
        collect.parse_exploitdb(EDB_CSV.replace("17491,", "abc,"))


def test_exploitdb_download_fills_the_table(con):
    session = FakeSession({collect.EXPLOITDB_URL: [FakeResponse(body=EDB_CSV.encode())]})
    assert collect.update_exploitdb(con, session) == 4
    assert con.execute("SELECT COUNT(*) FROM exploitdb").fetchone()[0] == 4
    assert db.get_meta(con, "exploitdb_updated")


OLD_EPSS_CSV = "cve,epss\nCVE-1,0.5\nCVE-2,0.1\nCVE-3,0.5\nCVE-4,0.9\n"


def test_oldest_epss_files_get_a_worked_out_percentile():
    notes, rows = collect.parse_epss(OLD_EPSS_CSV)
    assert notes == {}
    assert rows == [("CVE-1", 0.5, 0.75), ("CVE-2", 0.1, 0.25), ("CVE-3", 0.5, 0.75),
                    ("CVE-4", 0.9, 1.0)]


def test_epss_history_keeps_each_day_apart(con):
    may, june = date(2025, 5, 1), date(2025, 6, 1)
    session = FakeSession({
        collect.epss_url(may): [FakeResponse(body=gzip.compress(EPSS_CSV.encode()))] * 2,
        collect.epss_url(june): [FakeResponse(body=gzip.compress(OLD_EPSS_CSV.encode()))],
    })
    assert collect.update_epss_history(con, session, may) == 2
    assert collect.update_epss_history(con, session, june) == 4
    assert collect.update_epss_history(con, session, may) == 2  # again: replaced, not doubled
    counts = con.execute("SELECT date, COUNT(*) FROM epss_history GROUP BY date").fetchall()
    assert counts == [("2025-05-01", 2), ("2025-06-01", 4)]
    assert db.get_meta(con, "epss_model_2025-05-01") == "v2026.06.15"
    assert collect.epss_url(may).endswith("/epss_scores-2025-05-01.csv.gz")


def test_epss_history_for_a_day_without_scores_is_refused(con):
    day = date(2030, 1, 1)
    session = FakeSession({collect.epss_url(day): [FakeResponse(403)]})
    with pytest.raises(collect.DownloadError, match="no scores for 2030-01-01"):
        collect.update_epss_history(con, session, day)
