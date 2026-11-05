import sqlite3
import sys
from pathlib import Path

import pytest

from dingdongditch import db


def test_new_database_has_every_table():
    con = db.connect(":memory:")
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"meta", "cve", "cve_cpe", "kev", "epss", "exploitdb", "epss_history"}
    assert con.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


def test_meta_is_set_and_replaced():
    con = db.connect(":memory:")
    assert db.get_meta(con, "kev_version") is None
    db.set_meta(con, "kev_version", "2026.11.04")
    db.set_meta(con, "kev_version", "2026.11.05")
    assert db.get_meta(con, "kev_version") == "2026.11.05"


def test_reopening_keeps_the_data(tmp_path):
    path = tmp_path / "sub" / "vulns.db"
    con = db.connect(path)
    with con:
        db.set_meta(con, "hello", "world")
    con.close()
    con = db.connect(path)
    assert db.get_meta(con, "hello") == "world"
    con.close()


def test_other_schema_version_is_refused(tmp_path):
    path = tmp_path / "vulns.db"
    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 999")
    con.close()
    with pytest.raises(db.DatabaseError, match="Delete it"):
        db.connect(path)


def test_file_that_is_not_a_database_is_refused(tmp_path):
    path = tmp_path / "vulns.db"
    path.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(db.DatabaseError, match="not a dingdongditch database"):
        db.connect(path)


def test_env_var_wins(monkeypatch):
    monkeypatch.setenv(db.ENV_VAR, "/somewhere/else.db")
    assert db.default_path() == Path("/somewhere/else.db")


def test_default_path_is_per_user(monkeypatch):
    monkeypatch.delenv(db.ENV_VAR, raising=False)
    path = db.default_path()
    assert path.name == "vulns.db"
    assert path.parent.name == "dingdongditch"
    if sys.platform not in ("win32", "darwin"):
        monkeypatch.setenv("XDG_DATA_HOME", "/data")
        assert db.default_path() == Path("/data/dingdongditch/vulns.db")


def test_version_1_database_is_upgraded_and_keeps_its_data(tmp_path):
    path = tmp_path / "vulns.db"
    con = sqlite3.connect(path)
    con.executescript(db.SCHEMA.replace(db.EPSS_HISTORY, ""))
    con.execute("INSERT INTO kev VALUES ('CVE-1', 'v', 'p', 'n', 'd', 'Known')")
    con.execute("PRAGMA user_version = 1")
    con.commit()
    con.close()
    con = db.connect(path)
    assert con.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert con.execute("SELECT COUNT(*) FROM epss_history").fetchone() == (0,)
    assert con.execute("SELECT cve_id FROM kev").fetchall() == [("CVE-1",)]
    con.close()
