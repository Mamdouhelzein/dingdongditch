"""Karen mode: fetch each web port's home page for its title and telling headers.

One `GET /` per web port, read capped at probes.MAX_BYTES like every other probe.
Everything taken from the page is cleaned with probes.clean_banner.
"""

from __future__ import annotations

import asyncio
import html
import re
from collections.abc import Iterable

from dingdongditch import probes
from dingdongditch.fingerprints import identify_app, refine_with_app
from dingdongditch.nmap_parser import Service

WEB_NAMES = {"http", "https", "http-proxy"}
TITLE_MAX = 120

# Headers that tell you what's running (or how to log in), shown in the output.
TELLING_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
    "x-jenkins", "x-elastic-product", "www-authenticate", "location",
)

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title", re.IGNORECASE | re.DOTALL)


def parse_page(raw: bytes) -> tuple[str, dict[str, str], str]:
    """Split an HTTP response into (title, telling headers, body text)."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:  # some servers end lines with a bare \n
        head, sep, body = raw.partition(b"\n\n")

    headers: dict[str, str] = {}
    for line in head.split(b"\n")[1:]:
        key, sep, value = line.partition(b":")
        name = key.strip().decode("latin-1").lower()
        if sep and name in TELLING_HEADERS and name not in headers:
            headers[name] = probes.clean_banner(value.strip())

    title = ""
    m = _TITLE.search(body)
    if m:
        text = html.unescape(m.group(1).decode("utf-8", errors="replace"))
        title = probes.clean_banner(" ".join(text.split()).encode())[:TITLE_MAX]
    return title, headers, probes.clean_banner(body)


async def fetch_page(
    host: str, port: int, tls: bool, timeout: float = probes.TIMEOUT
) -> bytes:
    """GET / and return the raw response (empty if the connection fails)."""
    try:
        return await probes.exchange(
            host, port, tls, probes.http_request(host, "GET"), 0, timeout
        )
    except (*probes.TIMEOUT_ERRORS, OSError):
        return b""


async def _add_http_info(services: list[Service], concurrency: int, timeout: float) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service) -> None:
        async with sem:
            raw = await fetch_page(svc.host, svc.port, svc.tls, timeout)
        if not raw.startswith(b"HTTP/"):
            return
        svc.http_title, svc.http_headers, body = parse_page(raw)
        app = identify_app(svc.http_title, svc.http_headers, body)
        if app:
            refine_with_app(svc, app)

    await asyncio.gather(*(one(s) for s in services if s.name in WEB_NAMES))


def add_http_info(
    services: Iterable[Service],
    concurrency: int = probes.DEFAULT_CONCURRENCY,
    timeout: float = probes.TIMEOUT,
) -> list[Service]:
    """Fill in http_title / http_headers for web services and recognise the app behind them."""
    services = list(services)
    asyncio.run(_add_http_info(services, concurrency, timeout))
    return services
