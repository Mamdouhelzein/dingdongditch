import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from portrisk import scanner
from portrisk.cli import app

SAMPLE = Path(__file__).parent / "fixtures" / "sample_scan.xml"


def test_build_command_default_profile():
    cmd = scanner.build_command("192.168.56.101")
    assert cmd[:5] == ["nmap", "-sV", "--open", "-oX", "-"]
    assert "--top-ports" in cmd and cmd[-1] == "192.168.56.101"


def test_build_command_custom_ports_override_profile():
    cmd = scanner.build_command("10.0.0.5", profile="full", ports="22,80")
    assert ["-p", "22,80"] == cmd[5:7]
    assert "-p-" not in cmd


@pytest.mark.parametrize("bad", ["--script=evil", "-iL"])
def test_rejects_option_like_targets(bad):
    with pytest.raises(ValueError):
        scanner.build_command(bad)


def test_rejects_unknown_profile():
    with pytest.raises(ValueError):
        scanner.build_command("10.0.0.5", profile="turbo")


@pytest.fixture
def fake_nmap(monkeypatch):
    """Pretend nmap is installed and returns the sample XML."""
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/nmap")

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=SAMPLE.read_text(), stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)


def test_run_scan_parses_output(fake_nmap, tmp_path):
    out = tmp_path / "scan.xml"
    services = scanner.run_scan("192.168.56.101", save_xml=out)
    assert [s.port for s in services] == [21, 22, 23]
    assert out.exists()


def test_cli_scan(fake_nmap):
    result = CliRunner().invoke(app, ["scan", "192.168.56.101", "--json"])
    assert result.exit_code == 0
    assert '"product": "vsftpd"' in result.output


def test_cli_scan_without_nmap(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: None)
    result = CliRunner().invoke(app, ["scan", "192.168.56.101"])
    assert result.exit_code == 1
