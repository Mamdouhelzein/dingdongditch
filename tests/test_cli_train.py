"""`dingdongditch train`, on the small made-up world from test_train."""

import pytest
from test_train import make_frame
from typer.testing import CliRunner

from dingdongditch import db, features, train
from dingdongditch.cli import app


@pytest.fixture
def database(tmp_path, monkeypatch):
    """A database with one CVE, while load() hands back the made-up world."""
    path = tmp_path / "vulns.db"
    con = db.connect(path)
    with con:
        con.execute(
            "INSERT INTO cve (id, published, last_modified, status, description) "
            "VALUES ('CVE-1', 'p', 'm', 'Analyzed', 'd')"
        )
    con.close()
    monkeypatch.setattr(features, "load", lambda con, cutoff: make_frame())
    monkeypatch.setattr(train, "load", lambda con, cutoff: make_frame())
    return path


def run(*args):
    return CliRunner().invoke(app, ["train", *args])


def test_train_saves_a_model_next_to_the_database(database):
    result = run("--db", str(database))
    assert result.exit_code == 0, result.output
    assert "Trained a logistic regression model on 400 CVEs" in result.output
    saved = train.load_saved(database.with_name(train.MODEL_FILE))
    assert saved["settings"] == train.DEFAULT
    assert saved["cves"] == 400
    assert saved["exploited"] > 0
    assert len(train.scores(saved["model"], make_frame())) == 400


def test_xgboost_model_can_go_elsewhere(database, tmp_path):
    out = tmp_path / "models" / "mine.joblib"
    result = run("--db", str(database), "--xgboost", "--model", str(out))
    assert result.exit_code == 0, result.output
    assert "Trained an XGBoost model" in result.output
    assert train.load_saved(out)["settings"] == train.XGBOOST_BEST
    assert not database.with_name(train.MODEL_FILE).exists()


def test_time_travel_test_prints_the_comparison(database):
    result = run("--db", str(database), "--test", "2025-05-01")
    assert result.exit_code == 0, result.output
    assert "Standing on 2025-05-01" in result.output
    for name in ("CVSS", "Public exploit", "Our model"):
        assert name in result.output
    assert "No EPSS scores saved for 2025-05-01" in result.output
    assert not database.with_name(train.MODEL_FILE).exists()  # a test saves nothing


def test_test_year_must_be_over(database):
    result = run("--db", str(database), "--test", "2026-10-01")
    assert result.exit_code == 1
    assert "isn't over yet" in result.output


def test_bad_test_date_is_refused(database):
    result = run("--db", str(database), "--test", "May 2025")
    assert result.exit_code == 2
    assert "YYYY-MM-DD" in result.output


def test_missing_database_says_what_to_do(tmp_path):
    result = run("--db", str(tmp_path / "nothing.db"))
    assert result.exit_code == 1
    assert "update-db" in result.output
    assert not (tmp_path / "nothing.db").exists()


def test_empty_database_says_what_to_do(tmp_path):
    path = tmp_path / "empty.db"
    db.connect(path).close()
    result = run("--db", str(path))
    assert result.exit_code == 1
    assert "no CVEs" in result.output


def test_xgboost_missing_says_how_to_add_it(database, monkeypatch):
    monkeypatch.setattr(train, "xgboost_installed", lambda: False)
    result = run("--db", str(database), "--xgboost")
    assert result.exit_code == 1
    assert "pipx inject dingdongditch xgboost" in result.output
    assert not database.with_name(train.MODEL_FILE).exists()
