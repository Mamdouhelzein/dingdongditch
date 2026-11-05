"""Download NVD's CVE records from its JSON 2.0 feeds into the local database.

NVD publishes one gzipped file per year (CVE-2002 holds everything older) and a
"modified" file with the CVEs that changed in the last eight days. A first run
downloads every year, about 150 MB. Later runs within a week only need the
modified file. Each year file is also skipped when its checksum hasn't changed.

The files are up to 300 MB once unzipped, so they are read one CVE at a time
instead of all at once.
"""

from __future__ import annotations

import codecs
import gzip
import hashlib
import io
import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timedelta, timezone

import requests

from dingdongditch.collect import DownloadError, NotFound, fetch, utc_now
from dingdongditch.db import get_meta, set_meta

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{name}.{ext}"
FIRST_YEAR = 2002
RECENT_DAYS = 7  # the modified feed covers 8 days, so a week leaves a day to spare
CHUNK = 1 << 20

_GAP = re.compile(r"[\s,]*")
_CPE_SPLIT = re.compile(r"(?<!\\):")  # colons inside CPE fields are escaped as \:


def feed_names(con: sqlite3.Connection, today: datetime, full: bool = False) -> list[str]:
    """Which feeds to download: just "modified" if the last run was recent, else every year."""
    last = get_meta(con, "nvd_updated")
    if not full and last and today - datetime.fromisoformat(last) < timedelta(days=RECENT_DAYS):
        return ["modified"]
    return [str(year) for year in range(FIRST_YEAR, today.year + 1)]


def parse_meta(text: str) -> dict[str, str]:
    """A feed's .meta file (`key:value` lines) -> dict."""
    notes = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            notes[key.strip()] = value.strip()
    return notes


def iter_feed(chunks: Iterable[bytes]) -> Iterator[dict]:
    """Yield each item of an NVD feed's "vulnerabilities" list, reading it piece by piece."""
    decoder = json.JSONDecoder()
    text = codecs.getincrementaldecoder("utf-8")()
    pieces = iter(chunks)
    buf, pos = "", 0

    def more() -> bool:
        nonlocal buf, pos
        piece = next(pieces, None)
        if piece is None:
            return False
        buf, pos = buf[pos:] + text.decode(piece), 0
        return True

    while (start := buf.find('"vulnerabilities"')) < 0 or buf.find("[", start) < 0:
        if not more():
            raise DownloadError("The NVD feed has no list of vulnerabilities")
    pos = buf.find("[", start) + 1

    while True:
        pos = _GAP.match(buf, pos).end()
        if pos < len(buf) and buf[pos] == "]":
            return
        try:
            item, pos = decoder.raw_decode(buf, pos)
        except json.JSONDecodeError as exc:
            if not more():
                raise DownloadError(f"The NVD feed ends too early: {exc}") from exc
            continue
        yield item


def _best_cvss(metrics: list[dict]) -> tuple[float | None, str | None]:
    """NVD's own score if there is one, else the first one from the CVE's publisher."""
    if not metrics:
        return None, None
    best = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
    data = best.get("cvssData", {})
    return data.get("baseScore"), data.get("vectorString")


def cve_row(cve: dict) -> tuple:
    """One NVD CVE record -> a row for the cve table.

    NVD also copies CISA's KEV dates into each record (cisaExploitAdd ...). Those
    are left out on purpose: they would give the model the answer it should predict.
    """
    metrics = cve.get("metrics", {})
    cvss3 = _best_cvss(metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []))
    cvss2 = _best_cvss(metrics.get("cvssMetricV2", []))
    cvss4 = _best_cvss(metrics.get("cvssMetricV40", []))
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    cwes = dict.fromkeys(
        d["value"]
        for weakness in cve.get("weaknesses", [])
        for d in weakness.get("description", [])
        if d.get("value", "").startswith("CWE-")
    )
    references = cve.get("references", [])
    tags = sorted({tag for ref in references for tag in ref.get("tags", [])})
    return (
        cve["id"],
        cve["published"],
        cve["lastModified"],
        cve.get("vulnStatus", ""),
        description,
        *cvss3,
        *cvss2,
        *cvss4,
        " ".join(cwes),
        len(references),
        ";".join(tags),
    )


def cpe_rows(cve: dict) -> list[tuple]:
    """The products and versions a CVE affects -> rows for the cve_cpe table.

    Only matches NVD marks vulnerable are kept. "Only when running on X" platform
    matches are not vulnerable themselves, so they are skipped.
    """
    rows = {}
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                cpe = match["criteria"]
                fields = _CPE_SPLIT.split(cpe)
                if len(fields) < 6:
                    continue
                row = (
                    cve["id"],
                    fields[2],
                    fields[3],
                    fields[4],
                    cpe,
                    match.get("versionStartIncluding"),
                    match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"),
                    match.get("versionEndExcluding"),
                )
                rows[row] = None
    return list(rows)


def store(con: sqlite3.Connection, items: Iterable[dict]) -> int:
    """Save CVE records, keeping whichever copy of each CVE is newest. Returns how many."""
    count = 0
    for item in items:
        cve = item["cve"]
        old = con.execute("SELECT last_modified FROM cve WHERE id = ?", (cve["id"],)).fetchone()
        if old and old[0] > cve["lastModified"]:
            continue
        con.execute(
            "INSERT OR REPLACE INTO cve VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            cve_row(cve),
        )
        con.execute("DELETE FROM cve_cpe WHERE cve_id = ?", (cve["id"],))
        con.executemany("INSERT INTO cve_cpe VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", cpe_rows(cve))
        count += 1
    return count


def _unzipped_chunks(body: bytes, seen: Callable[[bytes], None]) -> Iterator[bytes]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as unzipped:
            while piece := unzipped.read(CHUNK):
                seen(piece)
                yield piece
    except (OSError, EOFError) as exc:
        raise DownloadError(f"The NVD download is damaged: {exc}") from exc


def update_feed(con: sqlite3.Connection, session: requests.Session, name: str) -> int | None:
    """Download one feed into the database. Returns how many CVEs, or None if unchanged."""
    notes = parse_meta(fetch(session, FEED_URL.format(name=name, ext="meta")).text)
    expected = notes.get("sha256", "").lower()
    if expected and get_meta(con, f"nvd_sha256_{name}") == expected:
        return None
    body = fetch(session, FEED_URL.format(name=name, ext="json.gz")).content
    sha256 = hashlib.sha256()
    chunks = _unzipped_chunks(body, sha256.update)
    try:
        with con:
            count = store(con, iter_feed(chunks))
            for _ in chunks:  # read the rest so the checksum covers the whole file
                pass
            if expected and sha256.hexdigest() != expected:
                raise DownloadError(f"The NVD {name} feed doesn't match its checksum")
            set_meta(con, f"nvd_sha256_{name}", expected)
    except (KeyError, TypeError, AttributeError) as exc:
        raise DownloadError(f"The NVD {name} feed wasn't in the expected format: {exc!r}") from exc
    return count


def update_nvd(
    con: sqlite3.Connection,
    session: requests.Session,
    full: bool = False,
    report: Callable[[str, int | None], None] = lambda name, count: None,
    today: datetime | None = None,
) -> int:
    """Bring the cve and cve_cpe tables up to date. Returns how many CVEs were saved.

    `report(name, count)` is called after each feed; count is None if it hadn't changed.
    """
    today = today or datetime.now(timezone.utc)
    total = 0
    for name in feed_names(con, today, full):
        try:
            count = update_feed(con, session, name)
        except NotFound:
            if name == str(today.year):  # a new year's file can take a few days to appear
                continue
            raise
        report(name, count)
        total += count or 0
    with con:
        set_meta(con, "nvd_updated", utc_now())
    return total
