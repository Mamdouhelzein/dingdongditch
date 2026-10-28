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
from collections.abc import Iterable

from dingdongditch.nmap_parser import Service
from dingdongditch.ports import SERVICE_NAMES

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"

DEFAULT_TIMEOUT = 1.0       # seconds to wait for each connection
DEFAULT_CONCURRENCY = 500   # connections in flight at once

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


async def scan_async(
    hosts: Iterable[str],
    ports: Iterable[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[tuple[str, int, str]]:
    """Check every (host, port) pair; return (host, port, state) sorted by host and port."""
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    ports = list(ports)
    # A fixed pool of workers pulls from one shared iterator, so a /16 with
    # thousands of ports doesn't create millions of tasks at once.
    pairs = ((h, p) for h in hosts for p in ports)
    results: list[tuple[str, int, str]] = []

    async def worker() -> None:
        for host, port in pairs:
            results.append((host, port, await check_port(host, port, timeout)))

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    results.sort(key=lambda r: (ipaddress.ip_address(r[0]), r[1]))
    return results


def scan(
    hosts: Iterable[str],
    ports: Iterable[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    only_open: bool = True,
) -> list[Service]:
    """Connect-scan `hosts` x `ports` and return the services, like the nmap engine does.

    `hosts` must be IP addresses (see targets.parse_targets). Product and
    version stay empty here; banner grabbing fills them in later.
    """
    results = asyncio.run(scan_async(hosts, ports, timeout, concurrency))
    return [
        Service(host=host, port=port, protocol="tcp", state=state,
                name=SERVICE_NAMES.get(port, ""))
        for host, port, state in results
        if state == OPEN or not only_open
    ]
