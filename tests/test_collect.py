"""The downloaders, fed by a fake session so no test touches the internet."""

import gzip
import json

import pytest
import requests

from dingdongditch import collect, db


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b""):
        self.status_code = status
        self.content = body

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self):
        return json.loads(self.content)


class FakeSession:
    """Answers each URL from a list of canned responses, in order."""

    def __init__(self, answers: dict[str, list]):
        self.answers = {url: list(items) for url, items in answers.items()}
        self.asked: list[str] = []

    def get(self, url, timeout=None):
        self.asked.append(url)
        answer = self.answers[url].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


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
