"""Risk levels, why and fix in `analyze` output, with a made-up NVD and model on disk."""

import json

import pytest
import risk_world
from typer.testing import CliRunner

from dingdongditch import db, train
from dingdongditch.cli import SHOWN, app

REPORT = """<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.7" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="443"><state state="open"/>
      <service name="https" product="Acme gateway" version="1.5">
        <cpe>cpe:/a:acme:gateway:1.5</cpe></service></port>
    <port protocol="tcp" portid="631"><state state="open"/>
      <service name="ipp" product="Printco printer" version="3.0">
        <cpe>cpe:/a:printco:printer:3.0</cpe></service></port>
    <port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh"/></port>
  </ports></host>
</nmaprun>
"""


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    folder = tmp_path_factory.mktemp("data")
    con = db.connect(folder / "vulns.db")
    saved = risk_world.fill(con)
    con.close()
    train.save(saved.pop("model"), folder / train.MODEL_FILE, saved)
    return folder


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text(REPORT)
    return str(path)


@pytest.fixture
def with_data(data_dir, monkeypatch):
    monkeypatch.setenv(db.ENV_VAR, str(data_dir / "vulns.db"))


def analyze(*args):
    return CliRunner().invoke(app, ["analyze", *args])


def test_table_shows_levels_why_and_fix(with_data, report):
    result = analyze(report)
    assert result.exit_code == 0, result.output
    out = " ".join(result.stdout.split())  # undo rich's line wrapping
    assert "KNOWN EXPLOITED │" in out and "│ 12 CVEs" in out  # the Risk column
    assert "no known CVEs" in out  # printer 3.0: NVD only lists 1.0
    assert "version unknown" in out  # ssh, no version
    assert "10.0.0.7:443 Acme gateway 1.5: 12 known CVEs (8 KNOWN EXPLOITED" in out
    assert "Why: on CISA's list of CVEs used in real attacks" in out
    assert "Fix: upgrade to 2.0 or later" in out
    assert f"...and {12 - SHOWN} more: --json lists them all." in out
    assert "matched on the version number alone" in out


def test_json_has_every_cve(with_data, report):
    result = analyze(report, "--json")
    assert result.exit_code == 0, result.output
    gateway, printer, ssh = json.loads(result.stdout)
    assert gateway["risk"]["level"] == "KNOWN EXPLOITED"
    assert len(gateway["risk"]["cves"]) == 12
    first = gateway["risk"]["cves"][0]
    assert (first["level"], first["fixed_in"], first["certain"]) == ("KNOWN EXPLOITED", "2.0", True)
    assert 0 <= first["riskier_than"] <= 1
    assert first["open_ended"] is False
    assert gateway["risk"]["possible_level"] is None
    assert printer["risk"] == ssh["risk"] == {"level": None, "possible_level": None, "cves": []}


ROUTER_REPORT = REPORT.replace(
    '<port protocol="tcp" portid="22">',
    """<port protocol="tcp" portid="8080"><state state="open"/>
      <service name="http" product="Netco router" version="3.0">
        <cpe>cpe:/a:netco:router:3.0</cpe></service></port>
    <port protocol="tcp" portid="22">""",
)


@pytest.fixture
def possible(data_dir, tmp_path):
    """A copy of the data where some CVEs match only through "before X" ranges."""
    copy = tmp_path / "vulns.db"
    copy.write_bytes((data_dir / "vulns.db").read_bytes())
    (tmp_path / train.MODEL_FILE).write_bytes((data_dir / train.MODEL_FILE).read_bytes())
    con = db.connect(copy)
    risk_world.add_open_ended(con)
    con.close()
    report = tmp_path / "scan.xml"
    report.write_text(ROUTER_REPORT)
    return str(report), str(copy)


def test_possible_matches_are_shown_apart(possible):
    report, database = possible
    result = analyze(report, "--db", database)
    assert result.exit_code == 0, result.output
    out = " ".join(result.stdout.split())
    # The gateway: its level and count come from the 12 sure CVEs, then 1 possible.
    assert "KNOWN EXPLOITED │" in out and "│ 12 CVEs" in out and "│ +1 possible: │" in out
    assert "Acme gateway 1.5: 12 known CVEs (8 KNOWN EXPLOITED" in out
    assert ", and 1 possible CVE (1 LOW)" in out
    # The router has no sure CVE, so the listed one doesn't make the port KNOWN EXPLOITED.
    assert "│ 2 possible: │ │ │ │ │ │ KNOWN EXPLOITED │" in out  # the level, on the next line
    assert (
        "10.0.0.7:8080 Netco router 3.0: no CVE names this version, "
        "2 possible CVEs (1 KNOWN EXPLOITED, 1 LOW)"
    ) in out
    assert out.count("Possible only: NVD's record doesn't say which release") == 2
    assert out.index("CVE-007 LOW") > out.index(f"...and {12 - SHOWN} more: --json")
    assert "Fix: upgrade to 9.0 or later" in out


def test_json_marks_possible_matches(possible):
    report, database = possible
    result = analyze(report, "--json", "--db", database)
    assert result.exit_code == 0, result.output
    gateway, _printer, router, _ssh = json.loads(result.stdout)
    assert (gateway["risk"]["level"], gateway["risk"]["possible_level"]) == (
        "KNOWN EXPLOITED", "LOW",
    )
    assert [c["open_ended"] for c in gateway["risk"]["cves"]] == [False] * 12 + [True]
    assert (router["risk"]["level"], router["risk"]["possible_level"]) == (
        None, "KNOWN EXPLOITED",
    )
    assert [c["cve_id"] for c in router["risk"]["cves"]] == ["CVE-005", "CVE-006"]


def test_without_a_database_the_scan_still_works(report):
    result = analyze(report, "--json")
    assert result.exit_code == 0, result.output
    assert all(svc["risk"] is None for svc in json.loads(result.stdout))
    assert "update-db" in result.stderr

    table = analyze(report)
    assert table.exit_code == 0, table.output
    assert "no risk data" in table.stdout


def test_database_text_cannot_restyle_the_output(data_dir, tmp_path, monkeypatch, report):
    copy = tmp_path / "vulns.db"
    copy.write_bytes((data_dir / "vulns.db").read_bytes())
    (tmp_path / train.MODEL_FILE).write_bytes((data_dir / train.MODEL_FILE).read_bytes())
    con = db.connect(copy)
    con.execute("UPDATE cve SET description = '[blink]Gateway[/blink] takeover. More.'")
    con.commit()
    con.close()
    monkeypatch.setenv(db.ENV_VAR, str(copy))
    result = analyze(report)
    assert result.exit_code == 0, result.output
    assert "[blink]Gateway[/blink] takeover" in result.stdout


def test_db_option_finds_the_database_and_model(data_dir, report):
    result = analyze(report, "--json", "--db", str(data_dir / "vulns.db"))
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)[0]["risk"]["level"] == "KNOWN EXPLOITED"


def test_missing_model_points_to_update_db(data_dir, tmp_path, report):
    copy = tmp_path / "vulns.db"
    copy.write_bytes((data_dir / "vulns.db").read_bytes())
    result = analyze(report, "--db", str(copy))
    assert result.exit_code == 0, result.output
    assert "run `dingdongditch update-db` or `dingdongditch train`" in result.stderr
