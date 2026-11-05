"""Download the public vulnerability data into the local database.

Every source is public and free, and nothing here touches a scanned host.
Each update replaces that source's rows in one transaction, so a failed
download leaves the old data in place.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone

import requests

from dingdongditch import __version__
from dingdongditch.db import set_meta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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
