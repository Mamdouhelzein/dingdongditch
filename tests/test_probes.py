import asyncio
import socket
import ssl
from pathlib import Path

import pytest

from dingdongditch import probes
from dingdongditch.nmap_parser import Service
from dingdongditch.probes import MAX_BYTES, add_banners, clean_banner, grab_banner

FIXTURES = Path(__file__).parent / "fixtures"
FAST = {"listen": 0.2, "timeout": 2.0}


def _server_tls() -> ssl.SSLContext:
    """Self-signed certificate made only for these tests."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(FIXTURES / "test_only_cert.pem", FIXTURES / "test_only_key.pem")
    return ctx


def run_with_server(handler, client, tls=False):
    """Start a fake service on localhost, run `client(port)` against it, return its result."""

    async def main():
        server = await asyncio.start_server(
            handler, "127.0.0.1", 0, ssl=_server_tls() if tls else None
        )
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await client(port)

    return asyncio.run(main())


def talks_first(banner: bytes):
    async def handler(reader, writer):
        writer.write(banner)
        await writer.drain()
        await asyncio.sleep(0.5)  # keep the connection open while the client reads
        writer.close()

    return handler


async def silent(reader, writer):
    await reader.read(100)
    writer.close()


# --- clean_banner ---------------------------------------------------------


def test_clean_banner_strips_line_endings():
    assert clean_banner(b"SSH-2.0-OpenSSH_7.4\r\n") == "SSH-2.0-OpenSSH_7.4"


def test_clean_banner_escapes_terminal_codes():
    assert clean_banner(b"\x1b[31mred\x00") == "\\x1b[31mred\\x00"
    assert clean_banner("evil‮txt".encode()) == "evil\\u202etxt"


def test_clean_banner_shows_invalid_utf8_as_hex():
    # Telnet option negotiation (IAC DO TERMINAL-TYPE).
    assert clean_banner(b"\xff\xfd\x18") == "\\xff\\xfd\\x18"


def test_clean_banner_keeps_binary_handshake_readable():
    # Start of a MySQL greeting: binary length/sequence, then the version string.
    assert "5.7.33" in clean_banner(b"J\x00\x00\x00\n5.7.33\x00")


# --- grab_banner ----------------------------------------------------------


def test_service_that_talks_first():
    banner = run_with_server(
        talks_first(b"220 (vsFTPd 2.3.4)\r\n"),
        lambda port: grab_banner("127.0.0.1", port, **FAST),
    )
    assert banner.text == "220 (vsFTPd 2.3.4)" and banner.tls is False


def test_silent_service_gives_empty_banner():
    # Unknown port: gets the HTTP probe, then a TLS retry, and both come back empty.
    banner = run_with_server(silent, lambda port: grab_banner("127.0.0.1", port, **FAST))
    assert banner.text == "" and banner.tls is False


def test_reads_at_most_max_bytes():
    banner = run_with_server(
        talks_first(b"A" * (MAX_BYTES * 3)),
        lambda port: grab_banner("127.0.0.1", port, **FAST),
    )
    assert len(banner.text) == MAX_BYTES


def test_tls_port_uses_tls(monkeypatch):
    async def client(port):
        monkeypatch.setattr(probes, "TLS_PORTS", {port})
        return await grab_banner("127.0.0.1", port, **FAST)

    banner = run_with_server(talks_first(b"* OK IMAP ready\r\n"), client, tls=True)
    assert banner.text == "* OK IMAP ready" and banner.tls is True


def test_closed_port_gives_empty_banner():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    banner = asyncio.run(grab_banner("127.0.0.1", port, **FAST))
    assert banner.text == ""


# --- probes for silent services ------------------------------------------


@pytest.mark.parametrize("port, expected", [
    (6379, probes.REDIS_PROBE),
    (11211, probes.BLANK_PROBE),   # memcached
    (22, probes.BLANK_PROBE),
])
def test_probe_choice(port, expected):
    assert probes.probe_for("10.0.0.1", port) == expected


@pytest.mark.parametrize("port", [80, 8080, 8443, 8983, 9200, 2375, 10000, 54321])
def test_web_and_unknown_ports_get_http_head(port):
    probe = probes.probe_for("10.0.0.1", port)
    assert probe.startswith(b"HEAD / HTTP/1.0\r\n") and b"Host: 10.0.0.1\r\n" in probe


def test_http_probe_brackets_ipv6():
    assert b"Host: [::1]\r\n" in probes.probe_for("::1", 80)


def answers(expected_request: bytes, reply: bytes):
    """A service that stays silent until it gets `expected_request`."""

    async def handler(reader, writer):
        request = await reader.read(1024)
        writer.write(reply if request.startswith(expected_request) else b"WRONG PROBE")
        await writer.drain()
        writer.close()

    return handler


def grab_as(monkeypatch, name, tls_ports=False):
    """Client that pretends the server's random port has the default name `name`."""

    async def client(port):
        monkeypatch.setattr(probes, "SERVICE_NAMES", {port: name} if name else {})
        if tls_ports:
            monkeypatch.setattr(probes, "TLS_PORTS", {port})
        return await grab_banner("127.0.0.1", port, **FAST)

    return client


def test_http_probe_gets_server_header(monkeypatch):
    reply = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n"
    banner = run_with_server(answers(b"HEAD / HTTP/1.0", reply), grab_as(monkeypatch, None))
    assert "Server: Apache/2.4.49 (Unix)" in banner.text


def test_redis_probe_gets_version(monkeypatch):
    reply = b"$40\r\n# Server\r\nredis_version:5.0.7\r\nredis_mode:standalone\r\n"
    banner = run_with_server(answers(b"INFO server\r\n", reply), grab_as(monkeypatch, "redis"))
    assert "redis_version:5.0.7" in banner.text


def test_redis_with_password_just_says_so(monkeypatch):
    reply = b"-NOAUTH Authentication required.\r\n"
    banner = run_with_server(answers(b"INFO server\r\n", reply), grab_as(monkeypatch, "redis"))
    assert banner.text == "-NOAUTH Authentication required."


def test_blank_line_probe(monkeypatch):
    banner = run_with_server(answers(b"\r\n", b"ERROR\r\n"), grab_as(monkeypatch, "memcached"))
    assert banner.text == "ERROR"


def test_tls_fallback_on_unusual_port(monkeypatch):
    # A TLS web server on a port we don't expect TLS on.
    reply = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
    banner = run_with_server(
        answers(b"HEAD / HTTP/1.0", reply), grab_as(monkeypatch, None), tls=True
    )
    assert banner.tls is True
    assert "Server: nginx/1.18.0" in banner.text


def test_no_tls_retry_for_silent_non_web_service(monkeypatch):
    connections = 0

    async def handler(reader, writer):
        nonlocal connections
        connections += 1
        await reader.read(100)
        writer.close()

    banner = run_with_server(handler, grab_as(monkeypatch, "mongodb"))
    assert banner.text == "" and banner.tls is False
    assert connections == 1


@pytest.mark.parametrize("raw, expected", [
    (b"\x15\x03\x01\x00\x02\x02\x46", True),
    (b"\x16\x03\x03\x00\x4a", True),
    (b"<html>The plain HTTP request was sent to HTTPS port</html>", True),
    (b"You're speaking plain HTTP to an SSL-enabled server port.", True),
    (b"SSH-2.0-OpenSSH_7.4", False),
    (b"", False),
])
def test_looks_like_tls(raw, expected):
    assert probes._looks_like_tls(raw) is expected


# --- add_banners ----------------------------------------------------------


def test_add_banners_fills_open_services_only():
    async def client(port):
        services = [
            Service("127.0.0.1", port, "tcp", "open", name="ssh"),
            Service("127.0.0.1", port, "tcp", "closed"),
        ]
        # add_banners runs its own event loop, so call it from a worker thread.
        return await asyncio.to_thread(add_banners, services, **FAST)

    services = run_with_server(talks_first(b"SSH-2.0-OpenSSH_7.4\r\n"), client)
    assert services[0].banner == "SSH-2.0-OpenSSH_7.4" and services[0].tls is False
    assert services[1].banner == ""
    assert services[0].to_dict()["banner"] == "SSH-2.0-OpenSSH_7.4"


def test_add_banners_rejects_zero_concurrency():
    with pytest.raises(ValueError):
        add_banners([], concurrency=0)
