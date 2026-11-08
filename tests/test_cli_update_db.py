"""`dingdongditch update-db`, with the downloaders replaced so nothing touches the internet."""

from datetime import date

import pytest
from typer.testing import CliRunner

from dingdongditch import cli, collect, db, nvd, train
from dingdongditch.cli import app
from dingdongditch.evaluate import EvaluationError


@pytest.fixture
def fake_sources(monkeypatch):
    """Each source adds one row instead of downloading anything."""
    calls = {}

    def kev(con, session):
        with con:
            con.execute("INSERT OR REPLACE INTO kev VALUES ('CVE-1', 'v', 'p', 'n', 'd', 'Known')")
        return 1

    def epss(con, session):
        raise collect.DownloadError("Couldn't download EPSS: HTTP 503")

    def exploitdb(con, session):
        return 0

    def update_nvd(con, session, full, report):
        calls["full"] = full
        report("2026", 1234)
        report("2025", None)
        with con:
            con.execute(
                "INSERT OR REPLACE INTO cve (id, published, last_modified, status, description) "
                "VALUES ('CVE-1', 'p', 'm', 'Analyzed', 'd')"
            )
        return 1234

    monkeypatch.setattr(collect, "update_kev", kev)
    monkeypatch.setattr(collect, "update_epss", epss)
    monkeypatch.setattr(collect, "update_exploitdb", exploitdb)
    monkeypatch.setattr(nvd, "update_nvd", update_nvd)

    def train_and_save(con, settings, out):  # real training is tested in test_cli_train
        calls["trained"] = (settings, out)
        return 1, 1

    monkeypatch.setattr(cli, "_train_and_save", train_and_save)
    return calls


def test_update_db_runs_every_source_and_reports_failures(tmp_path, fake_sources):
    path = tmp_path / "vulns.db"
    result = CliRunner().invoke(app, ["update-db", "--db", str(path)])
    assert result.exit_code == 1
    assert "CISA KEV: 1 exploited CVEs" in result.output
    assert "EPSS failed: Couldn't download EPSS: HTTP 503" in result.output
    assert "Exploit-DB: 0 CVEs with a public exploit" in result.output
    assert "NVD: 1,234 CVEs added or changed" in result.output
    assert "NVD 2026: 1,234 CVEs" in result.output
    assert "NVD 2025: unchanged" in result.output
    assert "Some sources failed" in result.output
    assert "CVEs: 1" in result.output
    assert "Exploited (KEV): 1" in result.output
    assert fake_sources["full"] is False
    con = db.connect(path)
    assert con.execute("SELECT cve_id FROM kev").fetchall() == [("CVE-1",)]
    con.close()


def test_update_db_uses_the_env_var_and_passes_full(tmp_path, fake_sources, monkeypatch):
    path = tmp_path / "from-env.db"
    monkeypatch.setenv(db.ENV_VAR, str(path))
    monkeypatch.setattr(collect, "update_epss", lambda con, session: 5)
    result = CliRunner().invoke(app, ["update-db", "--full"])
    assert result.exit_code == 0, result.output
    assert fake_sources["full"] is True
    assert path.exists()
    assert f"Database: {path}" in result.output.replace("\n", "")


def test_update_db_refuses_a_file_that_is_not_a_database(tmp_path, fake_sources):
    path = tmp_path / "notes.txt"
    path.write_text("my notes" * 100)
    result = CliRunner().invoke(app, ["update-db", "--db", str(path)])
    assert result.exit_code == 1
    assert "Can't open the database" in result.output


def test_update_db_also_saves_past_epss_scores(tmp_path, fake_sources, monkeypatch):
    asked = []

    def history(con, session, day):
        asked.append(day)
        return 7

    monkeypatch.setattr(collect, "update_epss_history", history)
    result = CliRunner().invoke(
        app,
        ["update-db", "--db", str(tmp_path / "v.db"),
         "--epss-date", "2025-05-01", "--epss-date", "2024-05-01"],
    )
    assert asked == [date(2025, 5, 1), date(2024, 5, 1)]
    assert "EPSS on 2025-05-01: 7 scored CVEs" in result.output
    assert "EPSS on 2024-05-01: 7 scored CVEs" in result.output


def test_update_db_refuses_a_bad_date(tmp_path, fake_sources):
    result = CliRunner().invoke(
        app, ["update-db", "--db", str(tmp_path / "v.db"), "--epss-date", "1 May 2025"]
    )
    assert result.exit_code == 2
    assert "YYYY-MM-DD" in result.output
    assert not (tmp_path / "v.db").exists()


def test_update_db_retrains_the_model_next_to_the_database(tmp_path, fake_sources):
    path = tmp_path / "vulns.db"
    result = CliRunner().invoke(app, ["update-db", "--db", str(path)])
    assert fake_sources["trained"] == (train.DEFAULT, path.with_name(train.MODEL_FILE))
    assert "Trained a logistic regression model on 1 CVEs" in result.output


def test_no_train_skips_training(tmp_path, fake_sources):
    CliRunner().invoke(app, ["update-db", "--db", str(tmp_path / "v.db"), "--no-train"])
    assert "trained" not in fake_sources


def test_no_training_without_cves(tmp_path, fake_sources, monkeypatch):
    monkeypatch.setattr(nvd, "update_nvd", lambda con, session, full, report: 0)
    result = CliRunner().invoke(app, ["update-db", "--db", str(tmp_path / "v.db")])
    assert "trained" not in fake_sources
    assert "No CVEs yet, so no risk model was trained" in result.output


def test_failed_training_is_reported(tmp_path, fake_sources, monkeypatch):
    def broken(con, settings, out):
        raise EvaluationError("No CVE was on CISA's KEV list before 2026-11-09")

    monkeypatch.setattr(collect, "update_epss", lambda con, session: 5)  # nothing else fails
    monkeypatch.setattr(cli, "_train_and_save", broken)
    result = CliRunner().invoke(app, ["update-db", "--db", str(tmp_path / "v.db")])
    assert result.exit_code == 1
    assert "Training failed: No CVE was on CISA's KEV list" in result.output
