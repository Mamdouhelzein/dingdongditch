"""Download the public vulnerability data into the local database.

Every source is public and free, and nothing here touches a scanned host.
Each update replaces that source's rows in one transaction, so a failed
download leaves the old data in place.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
import sqlite3
import time
from datetime import datetime, timezone

import requests

from dingdongditch import __version__
from dingdongditch.db import set_meta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

USER_AGENT = f"dingdongditch/{__version__} (+https://github.com/Mamdouhelzein/dingdongditch)"
TIMEOUT = 60.0
TRIES = 3
RETRY_WAIT = 10.0  # seconds, doubled after each failed try
_TRY_AGAIN = {429, 500, 502, 503, 504}


class DownloadError(Exception):
    """A source couldn't be downloaded or wasn't in the expected format."""


def new_session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


def _get(session: requests.Session, url: str) -> requests.Response:
    """GET a URL, trying again a few times if the server is busy or the network blips."""
    wait = RETRY_WAIT
    for attempt in range(TRIES):
        try:
            resp = session.get(url, timeout=TIMEOUT)
        except requests.RequestException as exc:
            problem = str(exc)
        else:
            if resp.status_code == 200:
                return resp
            problem = f"HTTP {resp.status_code}"
            if resp.status_code not in _TRY_AGAIN:
                break
        if attempt < TRIES - 1:
            time.sleep(wait)
            wait *= 2
    raise DownloadError(f"Couldn't download {url}: {problem}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_kev(data: dict) -> list[tuple[str, str, str, str, str, str]]:
    """CISA's KEV JSON -> rows for the kev table."""
    try:
        return [
            (
                item["cveID"],
                item.get("vendorProject", ""),
                item.get("product", ""),
                item.get("vulnerabilityName", ""),
                item["dateAdded"],
                item.get("knownRansomwareCampaignUse", "Unknown"),
            )
            for item in data["vulnerabilities"]
        ]
    except (KeyError, TypeError) as exc:
        raise DownloadError(f"The CISA KEV list wasn't in the expected format: {exc!r}") from exc


def update_kev(con: sqlite3.Connection, session: requests.Session) -> int:
    """Replace the kev table with CISA's current list. Returns how many CVEs it has."""
    resp = _get(session, KEV_URL)
    try:
        data = resp.json()
    except ValueError as exc:
        raise DownloadError(f"The CISA KEV list isn't valid JSON: {exc}") from exc
    rows = parse_kev(data)
    with con:
        con.execute("DELETE FROM kev")
        con.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?, ?, ?, ?)", rows)
        set_meta(con, "kev_version", str(data.get("catalogVersion", "")))
        set_meta(con, "kev_updated", _now())
    return len(rows)


def _unzip(body: bytes, what: str) -> str:
    """Gunzip a download if it's still zipped, and decode it as text."""
    try:
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        return body.decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise DownloadError(f"The {what} download is damaged: {exc}") from exc


def parse_epss(text: str) -> tuple[dict[str, str], list[tuple[str, float, float]]]:
    """The EPSS CSV -> (notes from its first line, rows for the epss table).

    The first line looks like `#model_version:v2026.06.15,score_date:2026-11-05T12:03:04Z`.
    """
    lines = text.splitlines()
    notes = {}
    if lines and lines[0].startswith("#"):
        for part in lines.pop(0)[1:].split(","):
            key, _, value = part.partition(":")
            notes[key.strip()] = value.strip()
    reader = csv.reader(lines)
    if next(reader, None) != ["cve", "epss", "percentile"]:
        raise DownloadError("The EPSS scores weren't in the expected format: unknown columns")
    try:
        rows = [(cve, float(score), float(percentile)) for cve, score, percentile in reader]
    except ValueError as exc:
        raise DownloadError(f"The EPSS scores weren't in the expected format: {exc}") from exc
    return notes, rows


def update_epss(con: sqlite3.Connection, session: requests.Session) -> int:
    """Replace the epss table with today's scores. Returns how many CVEs were scored."""
    notes, rows = parse_epss(_unzip(_get(session, EPSS_URL).content, "EPSS"))
    with con:
        con.execute("DELETE FROM epss")
        con.executemany("INSERT OR REPLACE INTO epss VALUES (?, ?, ?)", rows)
        set_meta(con, "epss_model", notes.get("model_version", ""))
        set_meta(con, "epss_date", notes.get("score_date", ""))
        set_meta(con, "epss_updated", _now())
    return len(rows)


# A few Exploit-DB entries have typos like "CVE-2015- 5698" or a broken dash, so
# anything that isn't a letter, digit or ';' may sit between the year and the number.
_EDB_CVE = re.compile(r"CVE-(\d{4})[^\w;]{1,3}(\d{4,7})(?!\d)", re.IGNORECASE)
_EDB_COLUMNS = {"id", "date_published", "type", "platform", "verified", "codes"}


def parse_exploitdb(text: str) -> list[tuple[int, str, str, str, str, int]]:
    """Exploit-DB's index CSV -> one row per (exploit, CVE) for the exploitdb table.

    Only the index is read: the exploit code itself is never downloaded.
    Exploits that name no CVE are skipped, because nothing could link them to a scan.
    """
    reader = csv.DictReader(io.StringIO(text))
    if not _EDB_COLUMNS <= set(reader.fieldnames or ()):
        raise DownloadError("The Exploit-DB index wasn't in the expected format: unknown columns")
    rows = {}
    try:
        for item in reader:
            for year, number in _EDB_CVE.findall(item["codes"] or ""):
                edb_id, cve = int(item["id"]), f"CVE-{year}-{number}"
                rows[edb_id, cve] = (
                    edb_id,
                    cve,
                    item["date_published"],
                    item["type"],
                    item["platform"],
                    int(item["verified"] == "1"),
                )
    except (ValueError, csv.Error) as exc:
        raise DownloadError(f"The Exploit-DB index wasn't in the expected format: {exc}") from exc
    return list(rows.values())


def update_exploitdb(con: sqlite3.Connection, session: requests.Session) -> int:
    """Replace the exploitdb table. Returns how many CVEs have at least one public exploit."""
    rows = parse_exploitdb(_unzip(_get(session, EXPLOITDB_URL).content, "Exploit-DB"))
    with con:
        con.execute("DELETE FROM exploitdb")
        con.executemany("INSERT INTO exploitdb VALUES (?, ?, ?, ?, ?, ?)", rows)
        set_meta(con, "exploitdb_updated", _now())
    return len({row[1] for row in rows})
