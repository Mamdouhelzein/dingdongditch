"""Karen mode: short conversations with services that only name their version after hello.

Each one does what an ordinary client does when it connects, keeps the lines
that name the software, and leaves. Nothing is joined, guessed, read or
changed. What the service said is added to its banner and fingerprinted again.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import Awaitable, Callable, Iterable

from dingdongditch import probes
from dingdongditch.fingerprints import fingerprint
from dingdongditch.nmap_parser import Service

# --- IRC --------------------------------------------------------------------
# A server only says what it runs once a client has registered (NICK + USER),
# and some look up the client's hostname and ident first, which takes a while.

IRC_TIME_LIMIT = 30.0
_IRC_KEEP = {"002", "004"}  # "Your host is X, running version Y" and "X Y <modes>"
_IRC_NICK_IN_USE = "433"


def _irc_nick() -> str:
    return f"ddd{random.randint(10000, 99999)}"


async def irc_hello(host: str, port: int, use_tls: bool, timeout: float) -> str:
    """Register as a visitor and return the lines that name the server's software."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host, port, ssl=probes.tls_context() if use_tls else None, limit=probes.MAX_BYTES,
        ),
        timeout,
    )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + IRC_TIME_LIMIT
    kept: list[str] = []

    async def send(line: str) -> None:
        writer.write(line.encode() + b"\r\n")
        await writer.drain()

    try:
        await send(f"NICK {_irc_nick()}")
        await send("USER dingdongditch 0 * :dingdongditch")
        received = 0
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, ValueError):  # ValueError: huge line
            while received < probes.MAX_BYTES:
                raw = await asyncio.wait_for(reader.readline(), max(deadline - loop.time(), 0))
                if not raw:
                    break
                received += len(raw)
                line = probes.clean_banner(raw)
                words = line.split(" ")
                if words[0] == "PING" and len(words) > 1:  # "are you still there?"
                    await send(f"PONG {words[1]}")
                elif line.startswith("ERROR"):
                    break
                elif len(words) > 1 and words[1] == _IRC_NICK_IN_USE:
                    await send(f"NICK {_irc_nick()}")
                elif len(words) > 1 and words[1] in _IRC_KEEP:
                    kept.append(line)
                    if words[1] == "004":
                        break
        with contextlib.suppress(OSError):
            await send("QUIT :bye")
    finally:
        writer.close()
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)
    return "\n".join(kept)


# --- Running them -------------------------------------------------------------

Conversation = Callable[[str, int, bool, float], Awaitable[str]]

# Service name -> the conversation that gets its version.
CONVERSATIONS: dict[str, Conversation] = {
    "irc": irc_hello,
}


async def _run(services: list[Service], concurrency: int, timeout: float) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service, talk: Conversation) -> None:
        async with sem:
            try:
                limit = IRC_TIME_LIMIT + timeout * 2
                text = await asyncio.wait_for(talk(svc.host, svc.port, svc.tls, timeout), limit)
            except (*probes.TIMEOUT_ERRORS, OSError, ValueError, EOFError):
                return
        if text:
            svc.banner = "\n".join(x for x in (svc.banner, text) if x)
            fingerprint([svc])

    await asyncio.gather(*(
        one(svc, CONVERSATIONS[svc.name])
        for svc in services
        if svc.state == "open" and svc.name in CONVERSATIONS and not svc.version
    ))


def add_versions(
    services: Iterable[Service],
    concurrency: int = probes.DEFAULT_CONCURRENCY,
    timeout: float = probes.TIMEOUT,
) -> list[Service]:
    """Talk to each open service that has a conversation and no version yet."""
    services = list(services)
    asyncio.run(_run(services, concurrency, timeout))
    return services
