"""End-to-end `dingdongditch scan` with the built-in engine, against fake local servers."""

import json
import socket
import threading

import pytest
from typer.testing import CliRunner

from dingdongditch import own_scanner
from dingdongditch.cli import app
from dingdongditch.ports import PROFILES


@pytest.fixture
def fake_ssh():
    """A tiny server on localhost that greets every connection like OpenSSH."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(20)
    srv.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.sendall(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield srv.getsockname()[1]
    stop.set()
    thread.join()
    srv.close()


def scan(*args):
    return CliRunner().invoke(app, ["scan", *args])


def test_own_engine_is_default_and_fingerprints(fake_ssh):
    result = scan("127.0.0.1", "-p", str(fake_ssh), "--json")
    assert result.exit_code == 0, result.output
    [svc] = json.loads(result.stdout)
    assert (svc["port"], svc["name"], svc["product"], svc["version"]) == (
        fake_ssh, "ssh", "OpenSSH", "7.4p1"
    )
    assert svc["cpes"] == ["cpe:/a:openbsd:openssh:7.4p1"]


def test_table_output(fake_ssh):
    result = scan("127.0.0.1", "-p", str(fake_ssh))
    assert result.exit_code == 0, result.output
    assert "OpenSSH 7.4p1" in result.stdout


def test_save_writes_json(fake_ssh, tmp_path):
    out = tmp_path / "scan.json"
    result = scan("127.0.0.1", "-p", str(fake_ssh), "-o", str(out))
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())[0]["product"] == "OpenSSH"


def test_several_targets_are_deduplicated(fake_ssh):
    result = scan("127.0.0.1,127.0.0.1", "127.0.0.1", "-p", str(fake_ssh), "--json")
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)) == 1


@pytest.mark.parametrize("args", [
    ["--", "-iL"],
    ["127.0.0.1", "-p", "0"],
    ["127.0.0.1", "-P", "turbo"],
    ["10.0.0.0/8"],
])
def test_bad_input_fails_cleanly(args):
    result = scan(*args)
    assert result.exit_code == 1
    assert "Scan failed" in result.output


def test_unknown_engine():
    assert scan("127.0.0.1", "--engine", "masscan").exit_code == 2


def test_resolve_profiles_and_no_chill():
    hosts, ports = own_scanner.resolve("127.0.0.1")
    assert hosts == ["127.0.0.1"] and ports == PROFILES["default"]
    assert own_scanner.resolve("127.0.0.1", "quick")[1] == PROFILES["quick"]
    assert own_scanner.resolve("127.0.0.1", no_chill=True)[1] == PROFILES["full"]
    # Custom ports win over --no-chill.
    assert own_scanner.resolve("127.0.0.1", ports="22,80", no_chill=True)[1] == [22, 80]


def test_options_reach_the_scanner(monkeypatch):
    seen = {}

    def fake_run_scan(hosts, ports, timeout, concurrency):
        seen.update(hosts=hosts, ports=ports, timeout=timeout, concurrency=concurrency)
        return []

    monkeypatch.setattr(own_scanner, "run_scan", fake_run_scan)
    result = scan("10.0.0.1 10.0.0.2", "--no-chill", "-t", "0.5", "-c", "50")
    assert result.exit_code == 0, result.output
    assert seen["hosts"] == ["10.0.0.1", "10.0.0.2"]
    assert len(seen["ports"]) == 65535
    assert (seen["timeout"], seen["concurrency"]) == (0.5, 50)
    assert "No open ports found." in result.stdout
