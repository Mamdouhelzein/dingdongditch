"""Ask each open port what it is: listen for a banner first, then send one safe probe.

Detect only: we send what a normal client sends first. No logins, no writes,
and at most MAX_BYTES are read per port.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Iterable
from dataclasses import dataclass

from dingdongditch.nmap_parser import Service
from dingdongditch.ports import TLS_PORTS

LISTEN_TIMEOUT = 2.0      # how long to wait for a service that talks first
TIMEOUT = 3.0             # connecting, and waiting for an answer to a probe
MAX_BYTES = 4096          # never read more than this from one port
DEFAULT_CONCURRENCY = 100  # lower than the port scan: each grab holds a connection longer

_QUIET_GAP = 0.3  # once a service has started talking, stop when it pauses this long
_TIMEOUTS = (asyncio.TimeoutError, TimeoutError)


@dataclass
class Banner:
    text: str = ""
    tls: bool = False


def clean_banner(raw: bytes) -> str:
    """Decode a banner and escape control characters so it's safe to print.

    A malicious service could otherwise send terminal escape codes.
    """
    out = []
    for ch in raw.decode("utf-8", errors="replace"):
        if ch == "\r":
            continue
        if ch in "\n\t" or ch.isprintable():
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out).strip()


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # Lab services use self-signed certificates and we only read, so don't verify.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _read(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """Read until EOF, MAX_BYTES, or the service goes quiet."""
    data = b""
    wait = timeout
    while len(data) < MAX_BYTES:
        try:
            chunk = await asyncio.wait_for(reader.read(MAX_BYTES - len(data)), wait)
        except (*_TIMEOUTS, OSError):
            break
        if not chunk:
            break
        data += chunk
        wait = _QUIET_GAP
    return data


async def _exchange(
    host: str, port: int, use_tls: bool, probe: bytes | None, listen: float, timeout: float
) -> bytes:
    """Connect, listen first, and send `probe` only if the service stays silent."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=_tls_context() if use_tls else None),
        timeout,
    )
    try:
        data = await _read(reader, listen)
        if not data and probe:
            writer.write(probe)
            await writer.drain()
            data = await _read(reader, timeout)
        return data
    finally:
        writer.close()
        with contextlib.suppress(*_TIMEOUTS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def grab_banner(
    host: str, port: int, listen: float = LISTEN_TIMEOUT, timeout: float = TIMEOUT
) -> Banner:
    """Return whatever the service at host:port says about itself (may be empty)."""
    use_tls = port in TLS_PORTS
    try:
        raw = await _exchange(host, port, use_tls, None, listen, timeout)
    except (*_TIMEOUTS, OSError):
        return Banner(tls=use_tls)
    return Banner(clean_banner(raw), use_tls)


async def _add_banners(
    services: list[Service], concurrency: int, listen: float, timeout: float
) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service) -> None:
        async with sem:
            svc.banner = (await grab_banner(svc.host, svc.port, listen, timeout)).text

    await asyncio.gather(
        *(one(s) for s in services if s.state == "open" and s.protocol == "tcp")
    )


def add_banners(
    services: Iterable[Service],
    concurrency: int = DEFAULT_CONCURRENCY,
    listen: float = LISTEN_TIMEOUT,
    timeout: float = TIMEOUT,
) -> list[Service]:
    """Fill in `banner` for every open TCP service and return the list."""
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    services = list(services)
    asyncio.run(_add_banners(services, concurrency, listen, timeout))
    return services
