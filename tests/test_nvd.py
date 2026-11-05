"""The NVD feed reader, fed small handmade feeds through a fake session."""

import gzip
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from http_fakes import FakeResponse, FakeSession

from dingdongditch import collect, db, nvd

TODAY = datetime(2026, 11, 5, tzinfo=timezone.utc)
VSFTPD = "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"
LINUX = "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"
OTHER = "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    monkeypatch.setattr(collect, "RETRY_WAIT", 0)


@pytest.fixture
def con():
    connection = db.connect(":memory:")
    yield connection
    connection.close()


def make_cve(cve_id="CVE-2011-2523", modified="2026-01-01T00:00:00.000", **extra):
    return {
        "id": cve_id,
        "published": "2011-07-05T00:00:00.000",
        "lastModified": modified,
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "Puerta trasera en vsftpd"},
            {"lang": "en", "value": "vsftpd 2.3.4 contains a backdoor. Ünïcode ✓"},
        ],
        "metrics": {
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"baseScore": 7.5, "vectorString": "SECOND"}},
                {"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "PRIMARY"}},
            ],
            "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 10.0}}],
        },
        "weaknesses": [
            {"description": [{"value": "CWE-78"}, {"value": "NVD-CWE-Other"}]},
            {"description": [{"value": "CWE-78"}, {"value": "CWE-506"}]},
        ],
        "references": [
            {"url": "https://a", "tags": ["Exploit", "Third Party Advisory"]},
            {"url": "https://b", "tags": ["Exploit"]},
            {"url": "https://c"},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {"vulnerable": True, "criteria": VSFTPD},
                            {"vulnerable": True, "criteria": VSFTPD},
                            {"vulnerable": False, "criteria": LINUX},
                        ],
                    },
                    {"negate": True, "cpeMatch": [{"vulnerable": True, "criteria": OTHER}]},
                ]
            }
        ],
        "cisaExploitAdd": "2026-01-01",
        **extra,
    }


def feed_bytes(*cves) -> bytes:
    return json.dumps(
        {"format": "NVD_CVE", "vulnerabilities": [{"cve": cve} for cve in cves]}, indent=2
    ).encode()


def feed_answers(name, raw: bytes, sha: str | None = None):
    sha = hashlib.sha256(raw).hexdigest().upper() if sha is None else sha
    meta = f"lastModifiedDate:2026-11-05T03:02:38-05:00\nsize:{len(raw)}\nsha256:{sha}\n"
    return {
        nvd.FEED_URL.format(name=name, ext="meta"): [FakeResponse(body=meta.encode())],
        nvd.FEED_URL.format(name=name, ext="json.gz"): [FakeResponse(body=gzip.compress(raw))],
    }


def pieces(raw: bytes, size: int):
    return [raw[i : i + size] for i in range(0, len(raw), size)]


@pytest.mark.parametrize("size", [1, 7, 100, 1 << 20])
def test_feed_is_read_one_cve_at_a_time_whatever_the_piece_size(size):
    raw = feed_bytes(make_cve("CVE-1"), make_cve("CVE-2"), make_cve("CVE-3"))
    ids = [item["cve"]["id"] for item in nvd.iter_feed(pieces(raw, size))]
    assert ids == ["CVE-1", "CVE-2", "CVE-3"]


def test_empty_feed_has_no_cves():
    assert list(nvd.iter_feed([b'{"vulnerabilities" : [ ] }'])) == []


def test_cut_off_feed_is_refused():
    raw = feed_bytes(make_cve("CVE-1"), make_cve("CVE-2"))
    with pytest.raises(collect.DownloadError, match="ends too early"):
        list(nvd.iter_feed(pieces(raw[:-200], 50)))


def test_feed_without_a_list_is_refused():
    with pytest.raises(collect.DownloadError, match="no list"):
        list(nvd.iter_feed([b"<html>maintenance</html>"]))


def test_cve_row_picks_the_useful_fields():
    row = nvd.cve_row(make_cve())
    assert row == (
        "CVE-2011-2523",
        "2011-07-05T00:00:00.000",
        "2026-01-01T00:00:00.000",
        "Analyzed",
        "vsftpd 2.3.4 contains a backdoor. Ünïcode ✓",
        9.8,
        "PRIMARY",
        10.0,
        None,
        None,
        None,
        "CWE-78 CWE-506",
        3,
        "Exploit;Third Party Advisory",
    )


def test_cve_with_almost_nothing_still_gives_a_row():
    cve = {"id": "CVE-1", "published": "p", "lastModified": "m"}
    assert nvd.cve_row(cve) == ("CVE-1", "p", "m", "", "", *[None] * 6, "", 0, "")


def test_cpe_rows_keep_only_vulnerable_products_once():
    assert nvd.cpe_rows(make_cve()) == [
        (
            "CVE-2011-2523",
            "a",
            "vsftpd_project",
            "vsftpd",
            VSFTPD,
            None,
            None,
            None,
            None,
        )
    ]


def test_cpe_rows_keep_version_ranges_and_escaped_colons():
    match = {
        "vulnerable": True,
        "criteria": r"cpe:2.3:a:acme:web\:server:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.0",
        "versionEndExcluding": "1.4.2",
    }
    cve = {"id": "CVE-1", "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}
    [row] = nvd.cpe_rows(cve)
    assert row[2:4] == ("acme", r"web\:server")
    assert row[5:] == ("1.0", None, None, "1.4.2")


def test_store_keeps_the_newest_copy(con):
    with con:
        nvd.store(con, [{"cve": make_cve(modified="2026-02-01T00:00:00.000")}])
        older = make_cve(modified="2026-01-01T00:00:00.000", vulnStatus="Modified")
        assert nvd.store(con, [{"cve": older}]) == 0
    assert con.execute("SELECT status FROM cve").fetchone() == ("Analyzed",)
    newer = make_cve(modified="2026-03-01T00:00:00.000", configurations=[])
    with con:
        assert nvd.store(con, [{"cve": newer}]) == 1
    assert con.execute("SELECT COUNT(*) FROM cve_cpe").fetchone() == (0,)


def test_feed_download_fills_the_tables(con):
    raw = feed_bytes(make_cve("CVE-1"), make_cve("CVE-2"))
    assert nvd.update_feed(con, FakeSession(feed_answers("2011", raw)), "2011") == 2
    assert con.execute("SELECT COUNT(*) FROM cve").fetchone() == (2,)
    assert con.execute("SELECT COUNT(*) FROM cve_cpe").fetchone() == (2,)
    assert db.get_meta(con, "nvd_sha256_2011") == hashlib.sha256(raw).hexdigest()


def test_unchanged_feed_is_not_downloaded_again(con):
    raw = feed_bytes(make_cve())
    nvd.update_feed(con, FakeSession(feed_answers("2011", raw)), "2011")
    session = FakeSession(feed_answers("2011", raw))
    assert nvd.update_feed(con, session, "2011") is None
    assert session.asked == [nvd.FEED_URL.format(name="2011", ext="meta")]


def test_feed_that_fails_its_checksum_saves_nothing(con):
    session = FakeSession(feed_answers("2011", feed_bytes(make_cve()), sha="AB" * 32))
    with pytest.raises(collect.DownloadError, match="checksum"):
        nvd.update_feed(con, session, "2011")
    assert con.execute("SELECT COUNT(*) FROM cve").fetchone() == (0,)
    assert db.get_meta(con, "nvd_sha256_2011") is None


def test_feed_with_a_broken_cve_saves_nothing(con):
    raw = feed_bytes(make_cve("CVE-1"), {"id": "CVE-2"})
    with pytest.raises(collect.DownloadError, match="expected format"):
        nvd.update_feed(con, FakeSession(feed_answers("2011", raw)), "2011")
    assert con.execute("SELECT COUNT(*) FROM cve").fetchone() == (0,)


def test_first_run_gets_every_year(con):
    names = nvd.feed_names(con, TODAY)
    assert names[0] == "2002"
    assert names[-1] == "2026"
    assert len(names) == 25


def test_recent_run_only_needs_the_modified_feed(con):
    db.set_meta(con, "nvd_updated", (TODAY - timedelta(days=3)).isoformat())
    assert nvd.feed_names(con, TODAY) == ["modified"]
    assert len(nvd.feed_names(con, TODAY, full=True)) == 25
    db.set_meta(con, "nvd_updated", (TODAY - timedelta(days=10)).isoformat())
    assert len(nvd.feed_names(con, TODAY)) == 25


def test_update_skips_this_years_missing_feed(con, monkeypatch):
    monkeypatch.setattr(nvd, "FIRST_YEAR", 2025)
    answers = feed_answers("2025", feed_bytes(make_cve()))
    answers[nvd.FEED_URL.format(name="2026", ext="meta")] = [FakeResponse(404)]
    reported = []
    total = nvd.update_nvd(
        con, FakeSession(answers), report=lambda *args: reported.append(args), today=TODAY
    )
    assert total == 1
    assert reported == [("2025", 1)]
    assert db.get_meta(con, "nvd_updated")


def test_update_stops_at_an_older_missing_feed(con, monkeypatch):
    monkeypatch.setattr(nvd, "FIRST_YEAR", 2025)
    answers = {nvd.FEED_URL.format(name="2025", ext="meta"): [FakeResponse(404)]}
    with pytest.raises(collect.NotFound):
        nvd.update_nvd(con, FakeSession(answers), today=TODAY)
    assert db.get_meta(con, "nvd_updated") is None
