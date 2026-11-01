"""Karen mode: safe checks for well-known misconfigurations, shown as CONFIRMED.

Detect only. Each check does the smallest exchange that proves the problem and
then leaves: no password guessing, and nothing is listed, read or changed.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Awaitable, Callable, Iterable

from dingdongditch import mongo_wire, probes
from dingdongditch.fingerprints import identify
from dingdongditch.nmap_parser import Finding, Service

BUDGET = 3  # a whole check gets this many timeouts, so a slow server can't hold us up

FTP_ANONYMOUS = Finding(
    check="ftp-anonymous",
    title="Anonymous FTP login allowed",
    why="Anyone can log in to this FTP server without an account.",
    fix="Disable anonymous access, e.g. anonymous_enable=NO in vsftpd.conf.",
)
OPEN_SHELL = Finding(
    check="open-shell",
    title="Open shell with no login",
    why="Anyone who connects gets a command prompt on this machine with no password. "
    "This is usually a backdoor.",
    fix="Find and stop whatever is listening on this port, and treat the machine "
    "as compromised until you know how it got there.",
)
REDIS_NO_PASSWORD = Finding(
    check="redis-no-password",
    title="Redis with no password",
    why="Anyone who can reach this port can read and change all its data, "
    "which is often enough to take over the server.",
    fix="Set a password (requirepass in redis.conf), and bind Redis to localhost "
    "or a private network.",
)

MONGODB_NO_AUTH = Finding(
    check="mongodb-no-auth",
    title="MongoDB with no authentication",
    why="Anyone who can reach this port can read and change every database.",
    fix="Turn on access control (security.authorization: enabled in mongod.conf), "
    "and bind MongoDB to localhost or a private network.",
)
TELNET_OPEN = Finding(
    check="telnet-open",
    title="Telnet open",
    why="Telnet sends passwords and everything else unencrypted, so anyone on the "
    "network path can read them.",
    fix="Turn telnet off and use SSH instead.",
)

_LOGIN_PROMPT = re.compile(r"(?:login|username|password)\s*:\s*$", re.IGNORECASE)
_REDIS_VERSION = re.compile(r"^redis_version:\d", re.MULTILINE)
_MONGO_VERSION = re.compile(r"\d+(?:\.\d+)+[\w.-]*")
_NO_SUCH_DATABASE = "dingdongditch-no-such-database"


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
        greeting_wait = max(timeout, probes.GREETING_TIMEOUT)
        if await _ftp_reply(reader, greeting_wait) != "220":
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


async def check_open_shell(svc: Service, timeout: float) -> Finding | None:
    """No traffic needed, and nothing is ever typed: the prompt it sent us is the proof."""
    fingerprint = identify(svc.banner)
    return OPEN_SHELL if fingerprint and fingerprint.name == "bindshell" else None


async def check_redis_no_password(svc: Service, timeout: float) -> Finding | None:
    """No traffic needed: banner grabbing already sent the read-only INFO server.

    Redis only answers that without a password if none is required. A real
    answer is a bulk reply ("$<length>") containing the version line.
    """
    proved = svc.banner.startswith("$") and _REDIS_VERSION.search(svc.banner)
    return REDIS_NO_PASSWORD if proved else None


async def check_mongodb_no_auth(svc: Service, timeout: float) -> Finding | None:
    """Ask MongoDB for something that needs a login, in a way that returns no data.

    authorizedDatabases=false makes a client without the right get an error
    instead of an empty list, and the filter matches no real database, so an
    open server has nothing to send back on versions that support it. Older ones
    ignore both and may send names, which decode_doc skips and never keeps.
    Along the way we learn the version, which doesn't need a login.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            svc.host, svc.port, ssl=probes.tls_context() if svc.tls else None,
            limit=probes.MAX_BYTES,
        ),
        timeout,
    )

    async def ask(message: bytes, request_id: int) -> tuple[dict, bool]:
        writer.write(message)
        await writer.drain()
        return await mongo_wire.read_reply(reader, request_id, timeout, probes.MAX_BYTES)

    try:
        hello, _ = await ask(mongo_wire.op_query({"isMaster": 1}, 1), 1)
        wire_version = hello.get("maxWireVersion")
        if hello.get("ok") != 1 or not isinstance(wire_version, int):
            return None  # not MongoDB: stop here
        modern = wire_version >= mongo_wire.FIRST_OP_MSG_WIRE_VERSION
        build = mongo_wire.op_msg if modern else mongo_wire.op_query

        command = {
            "listDatabases": 1,
            "nameOnly": True,
            "authorizedDatabases": False,
            "filter": {"name": _NO_SUCH_DATABASE},
        }
        answer, complete = await ask(build(command, 2), 2)
        no_auth = complete and answer.get("ok") == 1 and "databases" in answer

        svc.product = "MongoDB"
        # Last, because a long reply is cut off at our read limit (the version comes
        # first), and failing here must not undo what we've already proved.
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError, ValueError, EOFError):
            info, _ = await ask(build({"buildInfo": 1}, 3), 3)
            version = info.get("version")
            if isinstance(version, str) and _MONGO_VERSION.fullmatch(version):
                svc.version = version
                svc.cpes = [f"cpe:/a:mongodb:mongodb:{version}"]
        return MONGODB_NO_AUTH if no_auth else None
    finally:
        writer.close()
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


async def check_telnet_open(svc: Service, timeout: float) -> Finding | None:
    """No traffic needed, and no login: the greeting we already have is the proof.

    The name alone isn't, because a silent port 23 gets called telnet by default.
    It takes telnet's negotiation bytes, or a login prompt.
    """
    if svc.tls:
        return None  # the problem is cleartext
    fingerprint = identify(svc.banner)
    negotiated = fingerprint is not None and fingerprint.name == "telnet"
    return TELNET_OPEN if negotiated or _LOGIN_PROMPT.search(svc.banner) else None


Check = Callable[[Service, float], Awaitable["Finding | None"]]

# Service name -> checks to run on it.
CHECKS: dict[str, list[Check]] = {
    "ftp": [check_anonymous_ftp],
    "redis": [check_redis_no_password],
    "mongodb": [check_mongodb_no_auth],
    "telnet": [check_telnet_open],
    "bindshell": [check_open_shell],
}


async def _run_checks(services: list[Service], concurrency: int, timeout: float) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service, check: Check) -> None:
        async with sem:
            try:
                limit = timeout * BUDGET + probes.GREETING_TIMEOUT
                finding = await asyncio.wait_for(check(svc, timeout), limit)
            except (*probes.TIMEOUT_ERRORS, OSError, ValueError, EOFError):
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
