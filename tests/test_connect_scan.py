import asyncio
import errno
import socket

import pytest

from dingdongditch import connect_scan
from dingdongditch.connect_scan import (
    CLOSED,
    FILTERED,
    OPEN,
    Recheck,
    check_port,
    scan,
    scan_async,
)

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


def _limited_open_connection(limit):
    """Fake open_connection that fails with EMFILE above `limit` sockets in flight."""
    state = {"in_flight": 0, "peak": 0}

    async def fake(host, port):
        if state["in_flight"] >= limit:
            raise OSError(errno.EMFILE, "Too many open files")
        state["in_flight"] += 1
        state["peak"] = max(state["peak"], state["in_flight"])
        await asyncio.sleep(0.005)
        state["in_flight"] -= 1
        return None, _FakeWriter()

    return fake, state


def test_slows_down_instead_of_failing_when_out_of_sockets(monkeypatch):
    fake, state = _limited_open_connection(limit=20)
    monkeypatch.setattr(connect_scan.asyncio, "open_connection", fake)
    slowdowns = []

    results = asyncio.run(
        scan_async(["10.0.0.1"], range(1, 1001), concurrency=100, on_slowdown=slowdowns.append)
    )
    assert [p for _, p, _ in results] == list(range(1, 1001))  # every port, once
    assert all(s == OPEN for _, _, s in results)
    assert state["peak"] <= 20
    assert slowdowns and min(slowdowns) >= 1


def test_last_worker_waits_for_sockets(monkeypatch):
    calls = {"n": 0}

    async def flaky(host, port):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise OSError(errno.EMFILE, "Too many open files")
        return None, _FakeWriter()

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", flaky)
    results = asyncio.run(scan_async(["10.0.0.1"], [22, 80], concurrency=1))
    assert [(p, s) for _, p, s in results] == [(22, OPEN), (80, OPEN)]


def test_progress_callback(monkeypatch):
    async def fake(host, port):
        return None, _FakeWriter()

    monkeypatch.setattr(connect_scan.asyncio, "open_connection", fake)
    done = []
    asyncio.run(
        scan_async(["10.0.0.1", "10.0.0.2"], range(1, 51), on_result=lambda: done.append(1))
    )
    assert len(done) == 100


def test_raise_open_file_limit():
    resource = pytest.importorskip("resource")  # Linux/macOS only
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        new = connect_scan.raise_open_file_limit(soft + 10)
        expected = soft + 10 if hard == resource.RLIM_INFINITY else min(soft + 10, hard)
        assert new == expected
        # Never lowers an existing limit.
        assert connect_scan.raise_open_file_limit(1) == new
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_raise_open_file_limit_without_resource(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_resource(name, *args, **kwargs):
        if name == "resource":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_resource)
    assert connect_scan.raise_open_file_limit(2000) is None


# --- second try for ports that timed out ------------------------------------


class Target:
    """Fake target: open_ports answer, except those in `late`, which time out once."""

    def __init__(self, open_ports=(), late=(), silent=()):
        self.open_ports, self.late, self.silent = set(open_ports), set(late), set(silent)
        self.calls: list[int] = []
        self.in_flight = self.peak = 0

    async def __call__(self, host, port):
        self.calls.append(port)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            if port in self.silent or (port in self.late and self.calls.count(port) == 1):
                await asyncio.sleep(60)
            await asyncio.sleep(0)
            if port in self.open_ports or port in self.late:
                return None, _FakeWriter()
            raise ConnectionRefusedError
        finally:
            self.in_flight -= 1


@pytest.fixture
def quick_recheck(monkeypatch):
    monkeypatch.setattr(connect_scan, "RECHECK_TIMEOUT", 0.05)


def run_target(monkeypatch, target, ports, **kwargs):
    monkeypatch.setattr(connect_scan.asyncio, "open_connection", target)
    updates = []
    kwargs.setdefault("timeout", 0.02)
    results = asyncio.run(scan_async(["10.0.0.1"], ports, on_recheck=updates.append, **kwargs))
    return {port: state for _, port, state in results}, updates


def test_late_answer_is_caught_on_the_second_try(monkeypatch, quick_recheck):
    states, updates = run_target(monkeypatch, Target(late=[21, 80]), [21, 22, 80])
    assert states == {21: OPEN, 22: CLOSED, 80: OPEN}
    assert updates == [Recheck("started", 2), Recheck("done", 2, 2)]


def test_only_timed_out_ports_are_tried_again(monkeypatch, quick_recheck):
    target = Target(open_ports=[22], late=[21], silent=[23])
    states, _ = run_target(monkeypatch, target, [21, 22, 23, 25])
    assert states == {21: OPEN, 22: OPEN, 23: FILTERED, 25: CLOSED}
    assert sorted(target.calls) == [21, 21, 22, 23, 23, 25]


def test_really_silent_port_stays_filtered(monkeypatch, quick_recheck):
    states, updates = run_target(monkeypatch, Target(silent=[23]), [23])
    assert states == {23: FILTERED}
    assert updates[-1] == Recheck("done", 1, 0)


def test_second_try_is_calmer(monkeypatch, quick_recheck):
    monkeypatch.setattr(connect_scan, "RECHECK_CONCURRENCY", 3)
    ports = list(range(1, 21))
    target = Target(late=ports)
    monkeypatch.setattr(connect_scan.asyncio, "open_connection", target)
    peaks = []

    def on_recheck(update):
        if update.status == "started":
            target.peak = 0  # the first pass ran 20 at once; measure only the second
        else:
            peaks.append(target.peak)

    results = asyncio.run(
        scan_async(["10.0.0.1"], ports, timeout=0.02, concurrency=20, on_recheck=on_recheck)
    )
    assert peaks == [3]
    assert all(state == OPEN for _, _, state in results)


def test_second_try_never_uses_more_than_the_users_concurrency(monkeypatch, quick_recheck):
    target = Target(late=list(range(1, 11)))
    run_target(monkeypatch, target, list(range(1, 11)), concurrency=2)
    assert target.peak == 2


def test_second_try_waits_longer_but_keeps_a_more_patient_timeout(monkeypatch):
    seen = []

    async def fake_check(host, port, timeout):
        seen.append(timeout)
        return FILTERED

    monkeypatch.setattr(connect_scan, "check_port", fake_check)
    asyncio.run(scan_async(["10.0.0.1"], [80], timeout=1.0))
    assert seen == [1.0, connect_scan.RECHECK_TIMEOUT]
    seen.clear()
    asyncio.run(scan_async(["10.0.0.1"], [80], timeout=10.0))
    assert seen == [10.0, 10.0]


def test_too_many_timeouts_skip_the_second_try(monkeypatch, quick_recheck):
    monkeypatch.setattr(connect_scan, "MAX_RECHECKS", 2)
    target = Target(silent=[1, 2, 3])
    states, updates = run_target(monkeypatch, target, [1, 2, 3])
    assert set(states.values()) == {FILTERED}
    assert updates == [Recheck("skipped", 3)]
    assert sorted(target.calls) == [1, 2, 3]


def test_exactly_at_the_limit_still_rechecks(monkeypatch, quick_recheck):
    monkeypatch.setattr(connect_scan, "MAX_RECHECKS", 2)
    _, updates = run_target(monkeypatch, Target(silent=[1, 2]), [1, 2])
    assert updates[0] == Recheck("started", 2)


def test_nothing_timed_out_means_no_second_try(monkeypatch, quick_recheck):
    target = Target(open_ports=[22])
    states, updates = run_target(monkeypatch, target, [22, 23])
    assert states == {22: OPEN, 23: CLOSED}
    assert updates == [] and sorted(target.calls) == [22, 23]


def test_progress_counts_each_port_once(monkeypatch, quick_recheck):
    done = []
    run_target(monkeypatch, Target(late=[21]), [21, 22], on_result=lambda: done.append(1))
    assert len(done) == 2


def test_scan_reports_the_recovered_port_as_a_service(monkeypatch, quick_recheck):
    monkeypatch.setattr(connect_scan.asyncio, "open_connection", Target(late=[21]))
    services = scan(["10.0.0.1"], [21, 22], timeout=0.02)
    assert [(s.port, s.state, s.name) for s in services] == [(21, OPEN, "ftp")]
