"""Karen mode: short conversations with services that only name their version after hello.

Each one does what an ordinary client does when it connects, keeps the lines
that name the software, and leaves. Nothing is joined, guessed, read or
changed. What the service said is added to its banner and fingerprinted again.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import struct
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


# --- SMB ----------------------------------------------------------------------
# SMB1 servers name themselves when a client opens an anonymous session (no
# user, no password), the same handshake as nmap's smb-os-discovery. We read
# the names and hang up without opening any share. Servers with SMB1 turned
# off simply refuse, and keep their name to themselves.

_SMB_NEGOTIATE = 0x72
_SMB_SESSION_SETUP = 0x73
_SMB_FLAGS2 = 0x4001  # NT error codes, long names; plain-text strings, no extended security
_SMB_UNICODE = 0x8000
_SMB_EXTENDED_SECURITY = 0x80000000
NETBIOS_SESSION_PORTS = {139}


def _netbios(payload: bytes, kind: int = 0) -> bytes:
    """Wrap a message in the 4-byte NetBIOS session header SMB uses on both ports."""
    return bytes([kind]) + len(payload).to_bytes(3, "big") + payload


def _smb_message(command: int, words: bytes, data: bytes, uid: int = 0, mid: int = 1) -> bytes:
    header = (
        b"\xffSMB" + bytes([command]) + b"\0\0\0\0"  # status
        + bytes([0x18]) + struct.pack("<H", _SMB_FLAGS2)
        + b"\0" * 12  # PID high, signature, reserved
        + struct.pack("<HHHH", 0, 0xDDD, uid, mid)  # tree, process, user, message IDs
    )
    return _netbios(
        header + bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data
    )


SMB_NEGOTIATE = _smb_message(_SMB_NEGOTIATE, b"", b"\x02NT LM 0.12\x00")


def smb_session_setup(session_key: int) -> bytes:
    """Anonymous session setup: empty user, empty passwords."""
    words = struct.pack(
        "<BBHHHHIHHII",
        0xFF, 0, 0,  # no chained command
        0xFFFF, 2, 1,  # max buffer, max requests, virtual circuit
        session_key,
        0, 0,  # password lengths: none
        0, 0,  # reserved, capabilities
    )
    return _smb_message(_SMB_SESSION_SETUP, words, b"\0\0\0\0", mid=2)  # empty names


def _netbios_name(name: str) -> bytes:
    """NetBIOS 'first level' name encoding: 16 bytes, each split into two letters."""
    raw = name.upper().ljust(15).encode()[:15] + b"\x20"
    return b"\x20" + bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0xF))) + b"\0"


SMB_SESSION_REQUEST = _netbios(_netbios_name("*SMBSERVER") + _netbios_name("DINGDONGDITCH"), 0x81)


def _smb_parts(msg: bytes) -> tuple[int, int, bytes, bytes, int]:
    """(status, flags2, words, data, where data starts) of an SMB1 message."""
    if len(msg) < 35 or msg[:4] != b"\xffSMB":
        raise ValueError("not SMB1")
    status = int.from_bytes(msg[5:9], "little")
    flags2 = int.from_bytes(msg[10:12], "little")
    words_end = 33 + 2 * msg[32]
    count = int.from_bytes(msg[words_end : words_end + 2], "little")
    return status, flags2, msg[33:words_end], msg[words_end + 2 : words_end + 2 + count], \
        words_end + 2


def _smb_strings(data: bytes, unicode: bool, count: int) -> list[str]:
    """Up to `count` NUL-terminated strings, made safe to print."""
    found = []
    for _ in range(count):
        if unicode:
            end = next((i for i in range(0, len(data) - 1, 2) if data[i : i + 2] == b"\0\0"),
                       len(data) - len(data) % 2)
            text, data = data[:end].decode("utf-16-le", "backslashreplace"), data[end + 2 :]
        else:
            end = data.find(b"\0") if b"\0" in data else len(data)
            text, data = data[:end].decode("latin-1"), data[end + 1 :]
        found.append(" ".join(probes.clean_banner(text.encode()).split()))
    return found


async def _smb_read(reader: asyncio.StreamReader, timeout: float) -> tuple[int, bytes]:
    head = await asyncio.wait_for(reader.readexactly(4), timeout)
    length = int.from_bytes(head[1:], "big")
    if length > probes.MAX_BYTES:
        raise ValueError("SMB message too long")
    return head[0], await asyncio.wait_for(reader.readexactly(length), timeout)


async def smb_hello(host: str, port: int, use_tls: bool, timeout: float) -> str:
    """Negotiate SMB1, open an anonymous session, and return the names the server gave."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)

    async def ask(message: bytes) -> tuple[int, bytes]:
        writer.write(message)
        await writer.drain()
        return await _smb_read(reader, timeout)

    try:
        if port in NETBIOS_SESSION_PORTS:  # the old NetBIOS port wants a session request first
            kind, _ = await ask(SMB_SESSION_REQUEST)
            if kind != 0x82:  # positive session response
                return ""
        _, reply = await ask(SMB_NEGOTIATE)
        status, flags2, words, data, _ = _smb_parts(reply)
        if status or len(words) != 34 or words[:2] != b"\0\0":  # didn't pick NT LM 0.12
            return ""
        session_key, capabilities = struct.unpack_from("<II", words, 15)
        challenge_length = words[33]
        domain = ""
        if not capabilities & _SMB_EXTENDED_SECURITY:
            (domain,) = _smb_strings(data[challenge_length:], bool(flags2 & _SMB_UNICODE), 1)

        _, reply = await ask(smb_session_setup(session_key))
        _, flags2, _, data, start = _smb_parts(reply)
        unicode = bool(flags2 & _SMB_UNICODE)
        if unicode and start % 2:
            data = data[1:]  # padding so the UTF-16 strings start on an even byte
        native_os, lan_manager, session_domain = (_smb_strings(data, unicode, 3) + ["", "", ""])[:3]
    finally:
        writer.close()
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)

    lines = [("native os", native_os), ("lan manager", lan_manager),
             ("domain", session_domain or domain)]
    return "\n".join(f"smb {label}: {value}" for label, value in lines if value)


# --- Running them -------------------------------------------------------------

Conversation = Callable[[str, int, bool, float], Awaitable[str]]

# Service name -> the conversation that gets its version.
CONVERSATIONS: dict[str, Conversation] = {
    "irc": irc_hello,
    "netbios-ssn": smb_hello,
    "microsoft-ds": smb_hello,
}


async def _run(services: list[Service], concurrency: int, timeout: float) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service, talk: Conversation) -> None:
        async with sem:
            try:
                limit = IRC_TIME_LIMIT + timeout * 2  # IRC's is the longest conversation
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
