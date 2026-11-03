"""Questions for services that only answer in their own binary protocol, and their answers.

These services say nothing first and ignore a blank line, so we ask the one
read-only question that reveals what they are, the way a normal client would.
`describe()` turns an answer into readable text for the fingerprints, or returns
None if the bytes aren't an answer we asked for.
"""

from __future__ import annotations

import struct

# --- DNS ------------------------------------------------------------------
# The standard "what version are you?" question: TXT record "version.bind" in
# the CHAOS class. Over TCP, every DNS message starts with its 2-byte length.

DNS_ID = 0x6464  # "dd": a real reply carries our question's ID back
_DNS_QUERY = (
    struct.pack(">HHHHHH", DNS_ID, 0, 1, 0, 0, 0)  # ID, flags, 1 question, no records
    + b"\x07version\x04bind\x00"
    + struct.pack(">HH", 16, 3)  # type TXT, class CHAOS
)
DNS_VERSION_QUERY = struct.pack(">H", len(_DNS_QUERY)) + _DNS_QUERY

_DNS_RESULTS = {
    0: "no record", 1: "format error", 2: "server failure", 3: "no such name", 4: "not implemented",
    5: "refused",
}


def _skip_name(msg: bytes, pos: int) -> int:
    """Return where the domain name starting at `pos` ends."""
    while True:
        length = msg[pos]
        if length & 0xC0 == 0xC0:  # pointer to a name earlier in the message
            return pos + 2
        if length == 0:
            return pos + 1
        pos += 1 + length


def _txt(rdata: bytes) -> str:
    """A TXT record is one or more length-prefixed strings."""
    parts, pos = [], 0
    while pos < len(rdata):
        parts.append(rdata[pos + 1 : pos + 1 + rdata[pos]])
        pos += 1 + rdata[pos]
    text = b"".join(parts).decode("utf-8", errors="backslashreplace")
    return " ".join(text.split())  # one line, so it can't pose as another banner


def decode_dns(raw: bytes) -> str | None:
    """'version.bind: 9.4.2', or why there's no answer. None if it isn't our reply."""
    if len(raw) < 14:
        return None
    (length,) = struct.unpack_from(">H", raw)
    msg = raw[2 : 2 + length]
    if length < 12 or len(msg) < length:
        return None
    ident, flags, questions, answers = struct.unpack_from(">HHHH", msg)
    if ident != DNS_ID or not flags & 0x8000:  # 0x8000: this is a response
        return None
    try:
        pos = 12
        for _ in range(questions):
            pos = _skip_name(msg, pos) + 4  # type and class
        for _ in range(answers):
            pos = _skip_name(msg, pos)
            rtype, _, _, rdlength = struct.unpack_from(">HHIH", msg, pos)
            pos += 10
            if rtype == 16:
                return f"version.bind: {_txt(msg[pos : pos + rdlength])}"
            pos += rdlength
    except (IndexError, struct.error):
        pass  # a broken answer section: report it as no answer
    error = flags & 0x000F
    return f"version.bind: no answer ({_DNS_RESULTS.get(error, f'code {error}')})"


# --- PostgreSQL -----------------------------------------------------------
# PostgreSQL tells nobody its version before login. So we open with a startup
# message for protocol 4.0, which doesn't exist, and it refuses straight away,
# before any login. Its error names the source file and line it came from, and
# those differ between releases (fingerprints.py has the table).

PG_STARTUP = struct.pack(">II", 8, 4 << 16)  # length 8, protocol 4.0

_PG_FIELDS = {"S": "severity", "C": "code", "M": "message", "F": "file", "L": "line",
              "R": "routine"}


def decode_postgres(raw: bytes) -> str | None:
    """'postgresql error: FATAL 0A000: <message> (postmaster.c:1507 ProcessStartupPacket)'.

    None if `raw` isn't a complete PostgreSQL error message.
    """
    if len(raw) < 6 or raw[:1] != b"E":
        return None
    (length,) = struct.unpack_from(">I", raw, 1)
    body = raw[5 : 1 + length]
    if length < 5 or len(body) != length - 4 or not body.endswith(b"\x00\x00"):
        return None
    fields = {}
    for field in body[:-1].split(b"\x00")[:-1]:  # "S" "FATAL" \0 "C" "0A000" \0 ... \0
        if not field:
            return None
        key, value = field[:1].decode("latin-1"), field[1:].decode("utf-8", "backslashreplace")
        fields[_PG_FIELDS.get(key, key)] = " ".join(value.split())
    if "message" not in fields:
        return None
    text = f"postgresql error: {fields.get('severity', '')} {fields.get('code', '')}: "
    text += fields["message"]
    if "file" in fields and "line" in fields:
        where = [f"{fields['file']}:{fields['line']}", fields.get("routine", "")]
        text += f" ({' '.join(filter(None, where))})"
    return text


def describe(raw: bytes) -> str | None:
    """Readable text for a binary answer we asked for, or None."""
    return decode_dns(raw) or decode_postgres(raw)
