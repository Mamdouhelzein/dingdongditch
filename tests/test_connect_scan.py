import asyncio
import errno
import socket

import pytest

from dingdongditch import connect_scan
from dingdongditch.connect_scan import CLOSED, FILTERED, OPEN, check_port, scan, scan_async

# Windows waits ~2s before reporting a refused localhost connection.
SLOW_OK = 5.0


@pytest.fixture
def open_port():
    """A real listening socket on localhost; the OS completes the handshake for us."""
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(50)
        yield srv.getsockname()[1]


@pytest.fixture
def closed_port():
    """A localhost port that nothing is listening on."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_open_port(open_port):
    assert asyncio.run(check_port("127.0.0.1", open_port, SLOW_OK)) == OPEN


def test_closed_port(closed_port):
    assert asyncio.run(check_port("127.0.0.1", closed_port, SLOW_OK)) == CLOSED


class _FakeWriter:
    def close(self):
        pass

    async def wait_closed(self):
        pass


def test_no_answer_is_filtered(monkeypatch):
    async def hang(host, port):
        await asyncio.sleep(10)

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", hang)
    assert asyncio.run(check_port("10.0.0.1", 80, timeout=0.05)) == FILTERED


def test_unreachable_is_filtered(monkeypatch):
    async def unreachable(host, port):
        raise OSError(errno.EHOSTUNREACH, "No route to host")

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", unreachable)
    assert asyncio.run(check_port("10.0.0.1", 80)) == FILTERED


def test_out_of_file_descriptors_is_raised(monkeypatch):
    async def too_many(host, port):
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", too_many)
    with pytest.raises(OSError):
        asyncio.run(check_port("10.0.0.1", 80))


def test_scan_returns_services(open_port, closed_port):
    services = scan(["127.0.0.1"], [closed_port, open_port], timeout=SLOW_OK)
    assert [(s.host, s.port, s.protocol, s.state) for s in services] == [
        ("127.0.0.1", open_port, "tcp", "open")
    ]


def test_scan_names_known_ports_and_keeps_closed(monkeypatch):
    async def fake(host, port):
        if port == 22:
            return None, _FakeWriter()
        raise ConnectionRefusedError

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", fake)
    services = scan(["10.0.0.2", "10.0.0.1"], [6379, 22], only_open=False)
    assert [(s.host, s.port, s.state, s.name) for s in services] == [
        ("10.0.0.1", 22, "open", "ssh"),
        ("10.0.0.1", 6379, "closed", "redis"),
        ("10.0.0.2", 22, "open", "ssh"),
        ("10.0.0.2", 6379, "closed", "redis"),
    ]


def test_concurrency_limit_is_respected(monkeypatch):
    in_flight = peak = 0

    async def fake(host, port):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return None, _FakeWriter()

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", fake)
    results = asyncio.run(scan_async(["10.0.0.1"], range(1, 101), concurrency=7))
    assert len(results) == 100
    assert peak == 7


def test_rejects_zero_concurrency():
    with pytest.raises(ValueError):
        asyncio.run(scan_async(["10.0.0.1"], [80], concurrency=0))
