"""Find open TCP ports with a plain connect scan (no root needed).

Each port gets a normal TCP connection, the same handshake a browser does:
- open:     the connection worked
- closed:   the host refused it (RST)
- filtered: no answer before the timeout (usually a firewall)
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
from collections import deque
from collections.abc import Callable, Iterable

from dingdongditch.nmap_parser import Service
from dingdongditch.ports import SERVICE_NAMES

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"

DEFAULT_TIMEOUT = 1.0           # seconds to wait for each connection
DEFAULT_CONCURRENCY = 500       # connections in flight at once
KAREN_MODE_CONCURRENCY = 1000   # --karen-mode; lowered automatically if the OS can't keep up

# Out of file descriptors: a problem on our side, not a filtered port.
_OUR_FAULT = {errno.EMFILE, errno.ENFILE}


async def check_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Try one TCP connection and return open, closed or filtered."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return FILTERED
    except ConnectionRefusedError:
        return CLOSED
    except OSError as exc:
        if exc.errno in _OUR_FAULT:
            raise
        return FILTERED  # e.g. host or network unreachable
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return OPEN


def raise_open_file_limit(wanted: int) -> int | None:
    """Ask the OS to allow `wanted` open sockets (Linux/macOS soft limit, often 1024).

    Returns the new limit, or None where there's no such limit to raise (Windows).
    """
    try:
        import resource
    except ImportError:
        return None
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY:
        wanted = min(wanted, hard)
    if wanted > soft:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
            soft = wanted
        except (ValueError, OSError):
            pass
    return soft


async def scan_async(
    hosts: Iterable[str],
    ports: Iterable[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    on_result: Callable[[], None] | None = None,
    on_slowdown: Callable[[int], None] | None = None,
) -> list[tuple[str, int, str]]:
    """Check every (host, port) pair; return (host, port, state) sorted by host and port.

    If the OS runs out of sockets, workers retire one by one (down to 1) and the
    port is retried, so the scan settles just under the limit instead of failing.
    `on_result()` is called after each port, `on_slowdown(n)` when we drop to n workers.
    """
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    ports = list(ports)
    # A fixed pool of workers pulls from one shared iterator, so a /16 with
    # thousands of ports doesn't create millions of tasks at once.
    pairs = ((h, p) for h in hosts for p in ports)
    retry: deque[tuple[str, int]] = deque()
    results: list[tuple[str, int, str]] = []
    running = concurrency  # workers still in their loop

    def next_pair() -> tuple[str, int] | None:
        return retry.popleft() if retry else next(pairs, None)

    async def worker() -> None:
        nonlocal running
        try:
            while (pair := next_pair()) is not None:
                host, port = pair
                try:
                    state = await check_port(host, port, timeout)
                except OSError as exc:
                    if exc.errno not in _OUR_FAULT:
                        raise
                    retry.append(pair)
                    if running > 1:
                        # Retire; another running worker will pick up the retry.
                        if on_slowdown:
                            on_slowdown(running - 1)
                        return
                    await asyncio.sleep(0.1)  # last worker: wait for sockets to free up
                    continue
                results.append((host, port, state))
                if on_result:
                    on_result()
        finally:
            running -= 1

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    results.sort(key=lambda r: (ipaddress.ip_address(r[0]), r[1]))
    return results


def scan(
    hosts: Iterable[str],
    ports: Iterable[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    only_open: bool = True,
    on_result: Callable[[], None] | None = None,
    on_slowdown: Callable[[int], None] | None = None,
) -> list[Service]:
    """Connect-scan `hosts` x `ports` and return the services, like the nmap engine does.

    `hosts` must be IP addresses (see targets.parse_targets). Product and
    version stay empty here; banner grabbing fills them in later.
    """
    raise_open_file_limit(concurrency + 64)  # headroom for stdout, logs, etc.
    results = asyncio.run(
        scan_async(hosts, ports, timeout, concurrency, on_result, on_slowdown)
    )
    return [
        Service(host=host, port=port, protocol="tcp", state=state,
                name=SERVICE_NAMES.get(port, ""))
        for host, port, state in results
        if state == OPEN or not only_open
    ]
