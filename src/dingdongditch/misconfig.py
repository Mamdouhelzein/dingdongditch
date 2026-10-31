"""Karen mode: safe checks for well-known misconfigurations, shown as CONFIRMED.

Detect only. Each check does the smallest exchange that proves the problem and
then leaves: no password guessing, and nothing is listed, read or changed.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Awaitable, Callable, Iterable

from dingdongditch import probes
from dingdongditch.nmap_parser import Finding, Service

BUDGET = 3  # a whole check gets this many timeouts, so a slow server can't hold us up

FTP_ANONYMOUS = Finding(
    check="ftp-anonymous",
    title="Anonymous FTP login allowed",
    why="Anyone can log in to this FTP server without an account.",
    fix="Disable anonymous access, e.g. anonymous_enable=NO in vsftpd.conf.",
)
REDIS_NO_PASSWORD = Finding(
    check="redis-no-password",
    title="Redis with no password",
    why="Anyone who can reach this port can read and change all its data, "
    "which is often enough to take over the server.",
    fix="Set a password (requirepass in redis.conf), and bind Redis to localhost "
    "or a private network.",
)

_REDIS_VERSION = re.compile(r"^redis_version:\d", re.MULTILINE)


async def _ftp_reply(reader: asyncio.StreamReader, timeout: float) -> str:
    """Read one FTP reply (which may span several lines) and return its 3-digit code."""
    code = b""
    data = 0
    while data < probes.MAX_BYTES:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            return ""
        data += len(line)
        if not code:
            m = re.match(rb"(\d{3})([ -])", line)
            if not m:
                return ""
            code = m.group(1)
            if m.group(2) == b" ":
                return code.decode()
        elif line.startswith(code + b" "):  # "220-..." lines end at "220 ..."
            return code.decode()
    return ""


async def check_anonymous_ftp(svc: Service, timeout: float) -> Finding | None:
    """Log in as the public `anonymous` user and leave straight away."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            svc.host, svc.port, ssl=probes.tls_context() if svc.tls else None,
            limit=probes.MAX_BYTES,
        ),
        timeout,
    )

    async def send(command: bytes) -> str:
        writer.write(command + b"\r\n")
        await writer.drain()
        return await _ftp_reply(reader, timeout)

    try:
        if await _ftp_reply(reader, timeout) != "220":
            return None  # not an FTP server that's ready: send it nothing
        code = await send(b"USER anonymous")
        if code == "331":
            code = await send(b"PASS anonymous@")
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError, ValueError):
            await send(b"QUIT")
        return FTP_ANONYMOUS if code == "230" else None
    finally:
        writer.close()
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def check_redis_no_password(svc: Service, timeout: float) -> Finding | None:
    """No traffic needed: banner grabbing already sent the read-only INFO server.

    Redis only answers that without a password if none is required. A real
    answer is a bulk reply ("$<length>") containing the version line.
    """
    proved = svc.banner.startswith("$") and _REDIS_VERSION.search(svc.banner)
    return REDIS_NO_PASSWORD if proved else None


Check = Callable[[Service, float], Awaitable["Finding | None"]]

# Service name -> checks to run on it.
CHECKS: dict[str, list[Check]] = {
    "ftp": [check_anonymous_ftp],
    "redis": [check_redis_no_password],
}


async def _run_checks(services: list[Service], concurrency: int, timeout: float) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service, check: Check) -> None:
        async with sem:
            try:
                finding = await asyncio.wait_for(check(svc, timeout), timeout * BUDGET)
            except (*probes.TIMEOUT_ERRORS, OSError, ValueError):
                return  # couldn't prove it, so don't claim it
        if finding:
            svc.findings.append(finding)

    await asyncio.gather(*(
        one(svc, check)
        for svc in services if svc.state == "open"
        for check in CHECKS.get(svc.name, [])
    ))


def add_findings(
    services: Iterable[Service],
    concurrency: int = probes.DEFAULT_CONCURRENCY,
    timeout: float = probes.TIMEOUT,
) -> list[Service]:
    """Run the checks that apply to each open service and record what they prove."""
    services = list(services)
    asyncio.run(_run_checks(services, concurrency, timeout))
    return services
