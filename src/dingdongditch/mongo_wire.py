"""Just enough of MongoDB's wire protocol and BSON format to ask three questions.

Replies come from the target, so everything here assumes they're hostile: every
length is checked, and anything that doesn't add up raises ValueError.
"""

from __future__ import annotations

import asyncio
import struct

OP_REPLY = 1       # answer to OP_QUERY
OP_QUERY = 2004    # old way to send commands; since 5.1 only for hello/isMaster
OP_MSG = 2013      # current way, since 3.6
FIRST_OP_MSG_WIRE_VERSION = 6  # maxWireVersion of MongoDB 3.6

_HEADER = struct.Struct("<iiii")  # length, request id, response to, opcode
_INT32 = struct.Struct("<i")
_DOC_OFFSET = {OP_MSG: 5, OP_REPLY: 20}  # bytes between the header and the first document

# BSON element type -> size of its value, for types with a fixed size.
_FIXED_SIZES = {0x01: 8, 0x07: 12, 0x08: 1, 0x09: 8, 0x0A: 0, 0x10: 4, 0x11: 8, 0x12: 8, 0x13: 16}


def encode_doc(doc: dict) -> bytes:
    """BSON-encode a document of bools, ints, strings and nested documents."""
    body = b""
    for key, value in doc.items():
        name = key.encode() + b"\0"
        if isinstance(value, bool):
            body += b"\x08" + name + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + name + _INT32.pack(value)
        elif isinstance(value, str):
            data = value.encode() + b"\0"
            body += b"\x02" + name + _INT32.pack(len(data)) + data
        elif isinstance(value, dict):
            body += b"\x03" + name + encode_doc(value)
        else:
            raise TypeError(f"Can't encode {type(value).__name__}")
    return _INT32.pack(len(body) + 5) + body + b"\0"


def _value_size(data: bytes, pos: int, limit: int, kind: int) -> int | None:
    """How many bytes the value at `pos` takes, or None if the data stops first."""
    if kind in _FIXED_SIZES:
        return _FIXED_SIZES[kind]
    if kind not in (0x02, 0x03, 0x04, 0x05):
        raise ValueError(f"Unsupported BSON type {kind:#x}")
    if pos + 4 > limit:
        return None
    length = _INT32.unpack_from(data, pos)[0]
    if length < 0:
        raise ValueError("Negative BSON length")
    if kind == 0x02:
        return 4 + length
    return 5 + length if kind == 0x05 else length  # binary has an extra subtype byte


def _read_value(data: bytes, pos: int, size: int, kind: int) -> object:
    """Numbers, strings and bools; everything else is skipped, so it's never kept."""
    if kind == 0x01:
        return struct.unpack_from("<d", data, pos)[0]
    if kind == 0x02 and size >= 5:
        return data[pos + 4:pos + size - 1].decode("utf-8", errors="replace")
    if kind == 0x08:
        return data[pos] != 0
    if kind == 0x10:
        return _INT32.unpack_from(data, pos)[0]
    if kind == 0x12:
        return struct.unpack_from("<q", data, pos)[0]
    return None


def decode_doc(data: bytes) -> tuple[dict, bool]:
    """Read a document's top-level fields; return them and whether it was complete.

    A reply cut off by our read limit gives the fields before the cut. Raises
    ValueError if the data is malformed.
    """
    if len(data) < 5:
        raise ValueError("BSON document too short")
    total = _INT32.unpack_from(data, 0)[0]
    if total < 5:
        raise ValueError("Bad BSON length")
    complete = len(data) >= total
    limit = total - 1 if complete else len(data)  # the last byte is a terminating zero

    fields: dict = {}
    pos = 4
    while pos < limit:
        kind = data[pos]
        name_end = data.find(b"\0", pos + 1, limit)
        size = None
        if name_end >= 0:
            start = name_end + 1
            size = _value_size(data, start, limit, kind)
        if size is None or start + size > limit:
            if complete:
                raise ValueError("BSON element runs past the end of the document")
            return fields, False
        name = data[pos + 1:name_end].decode("utf-8", errors="replace")
        fields[name] = _read_value(data, start, size, kind)
        pos = start + size

    if complete and data[total - 1] != 0:
        raise ValueError("BSON document isn't terminated")
    return fields, complete


def _message(body: bytes, request_id: int, opcode: int) -> bytes:
    return _HEADER.pack(16 + len(body), request_id, 0, opcode) + body


def op_query(doc: dict, request_id: int) -> bytes:
    """A command on the admin database, the old way."""
    body = _INT32.pack(0) + b"admin.$cmd\0" + struct.pack("<ii", 0, -1) + encode_doc(doc)
    return _message(body, request_id, OP_QUERY)


def op_msg(doc: dict, request_id: int) -> bytes:
    """A command on the admin database, the current way."""
    body = struct.pack("<I", 0) + b"\0" + encode_doc({**doc, "$db": "admin"})
    return _message(body, request_id, OP_MSG)


async def read_reply(
    reader: asyncio.StreamReader, request_id: int, timeout: float, max_bytes: int
) -> tuple[dict, bool]:
    """Read the reply to `request_id`, at most `max_bytes` of it; see decode_doc."""
    header = await asyncio.wait_for(reader.readexactly(16), timeout)
    length, _, response_to, opcode = _HEADER.unpack(header)
    offset = _DOC_OFFSET.get(opcode)
    if offset is None or response_to != request_id or length <= 16 + offset:
        raise ValueError("Not a MongoDB reply to our request")

    body = await asyncio.wait_for(reader.readexactly(min(length - 16, max_bytes)), timeout)
    if opcode == OP_MSG and body[4] != 0:
        raise ValueError("Unexpected OP_MSG section")
    return decode_doc(body[offset:])
