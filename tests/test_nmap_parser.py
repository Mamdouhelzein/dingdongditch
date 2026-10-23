from pathlib import Path

import pytest
from typer.testing import CliRunner

from portrisk.cli import app
from portrisk.nmap_parser import parse_nmap_xml

SAMPLE = Path(__file__).parent / "fixtures" / "sample_scan.xml"


def test_parses_only_open_ports():
    services = parse_nmap_xml(SAMPLE)
    assert [s.port for s in services] == [21, 22, 23]


def test_extracts_product_version_and_cpe():
    ftp = parse_nmap_xml(SAMPLE)[0]
    assert ftp.host == "192.168.56.101"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"
    assert ftp.cpes == ["cpe:/a:vsftpd:vsftpd:2.3.4"]
    assert ftp.label == "vsftpd 2.3.4"


def test_include_closed_ports():
    services = parse_nmap_xml(SAMPLE, only_open=False)
    assert len(services) == 4


def test_rejects_non_nmap_xml(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<foo/>")
    with pytest.raises(ValueError):
        parse_nmap_xml(bad)


def test_cli_analyze_json():
    result = CliRunner().invoke(app, ["analyze", str(SAMPLE), "--json"])
    assert result.exit_code == 0
    assert '"product": "vsftpd"' in result.output
