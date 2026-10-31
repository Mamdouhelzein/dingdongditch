"""Ask each open port what it is: listen for a banner first, then send one safe probe.

Detect only: we send what a normal client sends first. No logins, no writes,
and at most MAX_BYTES are read per answer. Karen mode tries a few more safe
probes on ports the first one didn't identify.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

from dingdongditch.fingerprints import identify
from dingdongditch.nmap_parser import Service
from dingdongditch.ports import SERVICE_NAMES, TLS_PORTS

LISTEN_TIMEOUT = 2.0      # how long to wait for a service that talks first
TIMEOUT = 3.0             # connecting, and waiting for an answer to a probe
MAX_BYTES = 4096          # never read more than this from one port
DEFAULT_CONCURRENCY = 100  # lower than the port scan: each grab holds a connection longer

_QUIET_GAP = 0.3  # once a service has started talking, stop when it pauses this long
TIMEOUT_ERRORS = (asyncio.TimeoutError, TimeoutError)

# Default service names (from ports.py) that speak HTTP, so a HEAD request fits.
_WEB_NAMES = (
    "http", "kibana", "solr", "weblogic", "webmin", "glassfish", "elasticsearch",
    "couchdb", "docker", "consul", "etcd", "influxdb", "neo4j", "wsman", "activemq-web",
    "rabbitmq-mgmt", "hadoop", "jboss", "squid",
)
REDIS_PROBE = b"INFO server\r\n"  # read-only; answers with redis_version or "auth required"
BLANK_PROBE = b"\r\n"             # many services answer an empty line with an error naming them


def http_request(host: str, method: str = "HEAD") -> bytes:
    host_header = f"[{host}]" if ":" in host else host
    return (
        f"{method} / HTTP/1.0\r\nHost: {host_header}\r\n"
        "User-Agent: dingdongditch\r\n\r\n"
    ).encode()


def http_probe(host: str) -> bytes:
    return http_request(host, "HEAD")


def probe_for(host: str, port: int) -> bytes:
    """The one safe message to send if the service stays silent."""
    name = SERVICE_NAMES.get(port)
    if name == "redis":
        return REDIS_PROBE
    if name is None or any(web in name for web in _WEB_NAMES):
        return http_probe(host)  # unknown ports are most often web apps in labs
    return BLANK_PROBE


def extra_attempts(host: str) -> list[tuple[bool, bytes | None]]:
    """Karen mode: more (use_tls, probe) tries for ports the first probe didn't identify.

    Each is a fresh connection; we stop at the first answer we recognise.
    """
    http = http_probe(host)
    return [
        (False, http),
        (True, http),
        (False, REDIS_PROBE),
        (False, BLANK_PROBE),
        (True, None),  # TLS services that greet after the handshake (e.g. imaps)
    ]


_TLS_HINTS = (b"sent to HTTPS port", b"speaking plain HTTP to an SSL")  # nginx, Apache


def _looks_like_tls(raw: bytes) -> bool:
    """A TLS service answered our plain-text probe (TLS alert/handshake, or a web server hint)."""
    return raw[:2] in (b"\x15\x03", b"\x16\x03") or any(h in raw for h in _TLS_HINTS)


@dataclass
class Banner:
    text: str = ""
    tls: bool = False


def clean_banner(raw: bytes) -> str:
    """Decode a banner and escape control characters so it's safe to print.

    A malicious service could otherwise send terminal escape codes. Bytes that
    aren't valid UTF-8 (e.g. telnet negotiation) become \\xNN too, so the
    fingerprints can still see them.
    """
    out = []
    for ch in raw.decode("utf-8", errors="backslashreplace"):
        if ch == "\r":
            continue
        if ch in "\n\t" or ch.isprintable():
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out).strip()


@lru_cache(maxsize=1)
def tls_context() -> ssl.SSLContext:
    """A shared TLS client context for looking, not trusting.

    Lab services use self-signed certificates and we only read, so don't verify.
    Old services (TLS 1.0/1.1, weak ciphers) are common in labs and exactly what
    we want to find, so allow them too where the local OpenSSL still can.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ValueError, ssl.SSLError), warnings.catch_warnings():
        # Python warns that TLS 1.0 is deprecated, which is why we want to spot it.
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


async def _read(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """Read until EOF, MAX_BYTES, or the service goes quiet."""
    data = b""
    wait = timeout
    while len(data) < MAX_BYTES:
        try:
            chunk = await asyncio.wait_for(reader.read(MAX_BYTES - len(data)), wait)
        except (*TIMEOUT_ERRORS, OSError):
            break
        if not chunk:
            break
        data += chunk
        wait = _QUIET_GAP
    return data


async def exchange(
    host: str, port: int, use_tls: bool, probe: bytes | None, listen: float, timeout: float
) -> bytes:
    """Connect, listen first, and send `probe` only if the service stays silent.

    `listen=0` skips listening and sends the probe straight away.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=tls_context() if use_tls else None),
        timeout,
    )
    try:
        data = await _read(reader, listen) if listen > 0 else b""
        if not data and probe:
            writer.write(probe)
            await writer.drain()
            data = await _read(reader, timeout)
        return data
    finally:
        writer.close()
        with contextlib.suppress(*TIMEOUT_ERRORS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def _first_try(
    host: str, port: int, listen: float, timeout: float
) -> tuple[Banner | None, set[tuple[bool, bytes | None]]]:
    """The normal single probe (plus TLS fallback).

    Returns the banner (None if we couldn't connect at all) and the
    (use_tls, probe) pairs already tried.
    """
    use_tls = port in TLS_PORTS
    probe = probe_for(host, port)
    tried = {(use_tls, probe)}
    try:
        raw = await exchange(host, port, use_tls, probe, listen, timeout)
    except (*TIMEOUT_ERRORS, OSError):
        return None, tried

    sent_http = probe.startswith(b"HEAD ")
    if not use_tls and (_looks_like_tls(raw) or (sent_http and not raw)):
        # Maybe a TLS service on an unusual port (many just hang up on plain
        # text): try once more over TLS, and keep the plain answer if that fails.
        tried.add((True, probe))
        with contextlib.suppress(*TIMEOUT_ERRORS, OSError):
            tls_raw = await exchange(host, port, True, probe, listen, timeout)
            return Banner(clean_banner(tls_raw), True), tried
    return Banner(clean_banner(raw), use_tls), tried


async def grab_banner(
    host: str,
    port: int,
    listen: float = LISTEN_TIMEOUT,
    timeout: float = TIMEOUT,
    karen_mode: bool = False,
) -> Banner:
    """Return whatever the service at host:port says about itself (may be empty).

    In Karen mode, a port whose answer we can't identify gets the extra probes
    from extra_attempts() until one answer is recognised.
    """
    banner, tried = await _first_try(host, port, listen, timeout)
    if banner is None:
        return Banner(tls=port in TLS_PORTS)
    if not karen_mode or identify(banner.text):
        return banner

    for use_tls, probe in extra_attempts(host):
        if (use_tls, probe) in tried:
            continue
        try:
            # We already know it doesn't talk first, so don't wait long for a greeting.
            raw = await exchange(host, port, use_tls, probe, _QUIET_GAP, timeout)
        except (*TIMEOUT_ERRORS, OSError):
            continue
        text = clean_banner(raw)
        if identify(text):
            return Banner(text, use_tls)
        if text and not banner.text:
            banner = Banner(text, use_tls)  # better than nothing
    return banner


async def _add_banners(
    services: list[Service], concurrency: int, listen: float, timeout: float,
    karen_mode: bool,
) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service) -> None:
        async with sem:
            banner = await grab_banner(svc.host, svc.port, listen, timeout, karen_mode)
            svc.banner, svc.tls = banner.text, banner.tls

    await asyncio.gather(
        *(one(s) for s in services if s.state == "open" and s.protocol == "tcp")
    )


def add_banners(
    services: Iterable[Service],
    concurrency: int = DEFAULT_CONCURRENCY,
    listen: float = LISTEN_TIMEOUT,
    timeout: float = TIMEOUT,
    karen_mode: bool = False,
) -> list[Service]:
    """Fill in `banner` and `tls` for every open TCP service and return the list."""
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    services = list(services)
    asyncio.run(_add_banners(services, concurrency, listen, timeout, karen_mode))
    return services
