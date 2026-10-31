import pytest
from typer.testing import CliRunner

from dingdongditch import own_scanner
from dingdongditch.cli import app
from dingdongditch.nmap_parser import Service
from dingdongditch.os_guess import add_os_guess, clue_from
from dingdongditch.probes import clean_banner


def svc(port=22, banner=b"", name="ssh", host="10.0.0.5", **kwargs) -> Service:
    return Service(host, port, "tcp", "open", name=name, banner=clean_banner(banner), **kwargs)


def guess(*services) -> Service:
    return add_os_guess(services)[0]


@pytest.mark.parametrize("banner, expected", [
    (b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n", "Debian 9"),
    (b"SSH-2.0-OpenSSH_7.4p1 Debian-3\r\n", "Debian"),
    (b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "Ubuntu"),
    (b"SSH-2.0-OpenSSH_7.8 FreeBSD-20180909\r\n", "FreeBSD"),
    (b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n", "Windows"),
    (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n\r\n", "Ubuntu"),
    (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\n\r\n", "CentOS"),
    (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (Red Hat Enterprise Linux)\r\n\r\n", "Red Hat"),
    (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Win64) PHP/8.1\r\n\r\n", "Windows"),
    (b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n", "Windows"),
    (b"HTTP/1.1 200 OK\r\nX-Powered-By: ASP.NET\r\n\r\n", "Windows"),
    (b"220 mail.lab ESMTP Postfix (Debian/GNU)\r\n", "Debian"),
    (b"220 Microsoft FTP Service\r\n", "Windows"),
    (b"J\x00\x00\x00\x0a5.7.33-0ubuntu0.18.04.1\x00\x08\x00", "Ubuntu"),
    (b"Y\x00\x00\x00\x0a5.5.5-10.3.27-MariaDB-0+deb10u1\x00", "Debian 10"),
    (b"$900\r\n# Server\r\nredis_version:5.0.7\r\nos:Linux 5.15.0-91-generic x86_64\r\n", "Linux"),
    (b"$900\r\n# Server\r\nos:Darwin 23.1.0 arm64\r\n", "macOS"),
])
def test_banner_clues(banner, expected):
    assert guess(svc(banner=banner)).os_guess == expected


@pytest.mark.parametrize("banner", [
    b"",
    b"SSH-2.0-OpenSSH_7.4\r\n",
    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n",  # too vague to call
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
])
def test_no_clue_no_guess(banner):
    result = guess(svc(banner=banner))
    assert result.os_guess == "" and result.os_evidence == []


def test_clue_in_http_headers():
    result = guess(svc(80, name="http", http_headers={"x-powered-by": "ASP.NET"}))
    assert result.os_guess == "Windows"


@pytest.mark.parametrize("name, port", [("msrpc", 135), ("ms-wbt-server", 3389)])
def test_silent_windows_ports_are_a_clue(name, port):
    assert guess(svc(port, name=name)).os_guess == "Windows"


def test_banner_beats_port_hint_on_the_same_service():
    assert clue_from(svc(135, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4", name="msrpc")).distro == "Ubuntu"


def test_evidence_says_where_each_clue_came_from():
    result = guess(
        svc(80, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\n\r\n", name="http"),
        svc(22, b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"),
        svc(443, name="https"),
    )
    assert result.os_guess == "Debian 9"
    assert result.os_evidence == ["port 22 (ssh): Debian 9", "port 80 (http): Debian"]


def test_named_distro_beats_more_generic_linux_clues():
    redis = b"os:Linux 5.15.0 x86_64"
    result = guess(svc(6379, redis, "redis"), svc(6380, redis, "redis"),
                   svc(22, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"))
    assert result.os_guess == "Ubuntu"


def test_disagreement_goes_with_the_majority_and_stays_visible():
    linux = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\n\r\n"
    result = guess(svc(80, linux, "http"), svc(8080, linux, "http"), svc(135, name="msrpc"))
    assert result.os_guess == "Ubuntu"
    assert "port 135 (msrpc): Windows" in result.os_evidence


def test_each_host_gets_its_own_guess():
    services = add_os_guess([
        svc(host="10.0.0.1", banner=b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"),
        svc(host="10.0.0.2", banner=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
        svc(host="10.0.0.3", banner=b"SSH-2.0-OpenSSH_7.4"),
    ])
    assert [s.os_guess for s in services] == ["Debian 9", "Ubuntu", ""]


def test_every_port_on_the_host_gets_the_guess():
    services = add_os_guess([svc(22, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4"), svc(443, name="https")])
    assert {s.os_guess for s in services} == {"Ubuntu"}


def test_empty_scan():
    assert add_os_guess([]) == []


def test_only_karen_mode_guesses(monkeypatch):
    monkeypatch.setattr(own_scanner.connect_scan, "scan", lambda *a, **k: [svc(banner=b"")])
    monkeypatch.setattr(own_scanner.probes, "add_banners", lambda s, **k: s)
    monkeypatch.setattr(own_scanner.http_info, "add_http_info", lambda s, **k: s)
    monkeypatch.setattr(own_scanner.tls_info, "add_tls_info", lambda s, **k: s)

    def banner_from_ssh(services):
        for s in services:
            s.banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4"
        return services

    monkeypatch.setattr(own_scanner, "fingerprint", banner_from_ssh)
    assert own_scanner.run_scan(["10.0.0.5"], [22])[0].os_guess == ""
    assert own_scanner.run_scan(["10.0.0.5"], [22], karen_mode=True)[0].os_guess == "Ubuntu"


def test_table_prints_one_guess_per_host_and_labels_it(monkeypatch):
    services = add_os_guess([
        svc(22, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4"),
        svc(80, name="http"),
    ])
    monkeypatch.setattr(own_scanner, "run_scan", lambda *a, **k: services)
    result = CliRunner().invoke(app, ["scan", "10.0.0.5", "-p", "22,80"])
    assert result.exit_code == 0, result.output
    assert result.stdout.count("OS guess for 10.0.0.5: Ubuntu") == 1
    assert "port 22 (ssh): Ubuntu" in result.stdout
