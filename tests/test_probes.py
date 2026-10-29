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


def test_silent_service_gives_empty_banner(monkeypatch):
    monkeypatch.setattr(probes, "probe_for", lambda host, port: None, raising=False)
    banner = run_with_server(silent, lambda port: grab_banner("127.0.0.1", port, **FAST))
    assert banner.text == ""


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
    assert services[0].banner == "SSH-2.0-OpenSSH_7.4"
    assert services[1].banner == ""
    assert services[0].to_dict()["banner"] == "SSH-2.0-OpenSSH_7.4"


def test_add_banners_rejects_zero_concurrency():
    with pytest.raises(ValueError):
        add_banners([], concurrency=0)
