"""The local vulnerability database: one SQLite file that `update-db` fills.

Tables:
  cve        one row per CVE from NVD: dates, status, description, CVSS, CWEs, references
  cve_cpe    which products and versions each CVE affects (NVD's vulnerable CPE matches)
  kev        CISA's list of CVEs that were really exploited (the answer key for training)
  epss       FIRST.org's daily chance-of-exploitation score (what our model is compared with)
  exploitdb  public exploits from Exploit-DB and the CVEs they target (ids only, no code)
  meta       when each source was last downloaded, and similar notes
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

SCHEMA_VERSION = 1
ENV_VAR = "DINGDONGDITCH_DB"  # set it to use a different database file

SCHEMA = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE cve (
    id            TEXT PRIMARY KEY,
    published     TEXT NOT NULL,
    last_modified TEXT NOT NULL,
    status        TEXT NOT NULL,           -- NVD's vulnStatus, e.g. Analyzed or Rejected
    description   TEXT NOT NULL,
    cvss3_score   REAL,
    cvss3_vector  TEXT,
    cvss2_score   REAL,
    cvss2_vector  TEXT,
    cvss4_score   REAL,
    cvss4_vector  TEXT,
    cwes          TEXT NOT NULL DEFAULT '', -- space separated, e.g. 'CWE-79 CWE-89'
    ref_count     INTEGER NOT NULL DEFAULT 0,
    ref_tags      TEXT NOT NULL DEFAULT ''  -- ';' separated, e.g. 'Exploit;Patch'
);

CREATE TABLE cve_cpe (
    cve_id                  TEXT NOT NULL,
    part                    TEXT NOT NULL,  -- a = application, o = OS, h = hardware
    vendor                  TEXT NOT NULL,
    product                 TEXT NOT NULL,
    cpe                     TEXT NOT NULL,  -- the full CPE 2.3 name
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT
);
CREATE INDEX cve_cpe_product ON cve_cpe (vendor, product);
CREATE INDEX cve_cpe_cve ON cve_cpe (cve_id);

CREATE TABLE kev (
    cve_id     TEXT PRIMARY KEY,
    vendor     TEXT NOT NULL,
    product    TEXT NOT NULL,
    name       TEXT NOT NULL,
    date_added TEXT NOT NULL,
    ransomware TEXT NOT NULL               -- 'Known' or 'Unknown'
);

CREATE TABLE epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL
);

CREATE TABLE exploitdb (
    edb_id    INTEGER NOT NULL,
    cve_id    TEXT NOT NULL,
    published TEXT NOT NULL,
    type      TEXT NOT NULL,               -- e.g. remote, local, webapps, dos
    platform  TEXT NOT NULL,
    verified  INTEGER NOT NULL,
    PRIMARY KEY (edb_id, cve_id)
);
CREATE INDEX exploitdb_cve ON exploitdb (cve_id);
"""


class DatabaseError(Exception):
    """The database file can't be used as it is."""


def default_path() -> Path:
    """Where the database lives unless DINGDONGDITCH_DB says otherwise."""
    if override := os.environ.get(ENV_VAR):
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "dingdongditch" / "vulns.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open the database, creating it and its tables the first time."""
    path = default_path() if path is None else path
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    try:
        version = con.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            with con:
                con.executescript(SCHEMA)
                con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    except sqlite3.DatabaseError as exc:
        con.close()
        raise DatabaseError(f"{path} is not a dingdongditch database: {exc}") from exc
    if version not in (0, SCHEMA_VERSION):
        con.close()
        raise DatabaseError(
            f"{path} was made by a different version of dingdongditch. "
            "Delete it and run `dingdongditch update-db` again."
        )
    return con


def get_meta(con: sqlite3.Connection, key: str) -> str | None:
    row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(con: sqlite3.Connection, key: str, value: str) -> None:
    con.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
