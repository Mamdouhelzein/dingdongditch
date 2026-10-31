"""MongoDB check, against a fake server that speaks the real binary protocol."""

import asyncio
import json
import random
import socketserver
import struct
import threading

import pytest
from typer.testing import CliRunner

from dingdongditch import misconfig, mongo_wire
from dingdongditch.cli import app
from dingdongditch.fingerprints import identify
from dingdongditch.misconfig import MONGODB_NO_AUTH
from dingdongditch.mongo_wire import decode_doc, encode_doc
from dingdongditch.nmap_parser import Service

MODERN, OLD = 17, 5  # maxWireVersion of MongoDB 6.0 and 3.4


def bson(fields: dict, *raw_elements: bytes) -> bytes:
    """encode_doc plus raw elements for types it doesn't write (doubles, arrays)."""
    body = encode_doc(fields)[4:-1] + b"".join(raw_elements)
    return struct.pack("<i", len(body) + 5) + body + b"\0"


def ok(value: float = 1.0) -> bytes:
    return b"\x01ok\0" + struct.pack("<d", value)  # real servers send ok as a double


def db_list(*names: str) -> bytes:
    items = b"".join(
        b"\x03" + str(i).encode() + b"\0" + encode_doc({"name": name})
        for i, name in enumerate(names)
    )
    array = struct.pack("<i", len(items) + 5) + items + b"\0"
    return b"\x04databases\0" + array


UNAUTHORIZED = bson({"errmsg": "command listDatabases requires authentication", "code": 13},
                    ok(0.0))


class FakeMongo:
    """A threaded fake mongod on localhost. Records every command it gets."""

    def __init__(self, wire=MODERN, auth=False, version="4.4.6", dbs=(), replies=None):
        self.commands: list[str] = []
        self.opcodes: list[int] = []
        self.requests: list[bytes] = []
        answers = {
            "isMaster": bson({"ismaster": True, "maxWireVersion": wire}, ok()),
            "listDatabases": UNAUTHORIZED if auth else bson({}, db_list(*dbs), ok()),
            "buildInfo": bson({"version": version}, ok()),
            **(replies or {}),
        }
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                try:
                    while len(header := self.rfile.read(16)) == 16:
                        if header.startswith((b"HEAD", b"GET ")):  # what real mongod says to HTTP
                            self.wfile.write(
                                b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nIt looks like you "
                                b"are trying to access MongoDB over HTTP on the native driver "
                                b"port.\r\n"
                            )
                            return
                        length, rid, _, opcode = struct.unpack("<iiii", header)
                        body = self.rfile.read(length - 16)
                        fake.requests.append(body)
                        fake.opcodes.append(opcode)
                        # OP_QUERY: 4 flag bytes, collection name, 8 bytes of paging.
                        name_end = body.find(b"\0", 4)
                        skip = 5 if opcode == mongo_wire.OP_MSG else name_end + 1 + 8
                        command = next(iter(decode_doc(body[skip:])[0]))
                        fake.commands.append(command)
                        self.wfile.write(fake.reply(answers[command], rid, opcode))
                except (OSError, ValueError, KeyError):
                    pass

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]

    @staticmethod
    def reply(doc: bytes, rid: int, opcode: int) -> bytes:
        if opcode == mongo_wire.OP_MSG:
            payload, out = struct.pack("<I", 0) + b"\0" + doc, mongo_wire.OP_MSG
        else:
            payload, out = struct.pack("<iqii", 8, 0, 0, 1) + doc, mongo_wire.OP_REPLY
        return struct.pack("<iiii", 16 + len(payload), 99, rid, out) + payload

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def check(fake: FakeMongo) -> Service:
    with fake:
        svc = Service("127.0.0.1", fake.port, "tcp", "open", name="mongodb")
        asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=2.0))
    return svc


# --- the check ----------------------------------------------------------------


def test_open_mongodb_is_confirmed_with_version():
    svc = check(FakeMongo(version="4.4.6"))
    assert svc.findings == [MONGODB_NO_AUTH]
    assert (svc.product, svc.version) == ("MongoDB", "4.4.6")
    assert svc.cpes == ["cpe:/a:mongodb:mongodb:4.4.6"]


def test_login_required_is_not_a_finding_but_version_is_known():
    svc = check(FakeMongo(auth=True, version="6.0.1"))
    assert svc.findings == []
    assert (svc.product, svc.version) == ("MongoDB", "6.0.1")


def test_sends_only_the_three_questions():
    fake = FakeMongo()
    check(fake)
    assert fake.commands == ["isMaster", "listDatabases", "buildInfo"]


def test_the_question_can_return_no_real_data():
    fake = FakeMongo()
    check(fake)
    request = fake.requests[1]
    assert b"dingdongditch-no-such-database" in request  # filter matching nothing
    # Must be false: without it a locked server can answer "ok, empty list".
    position = request.index(b"authorizedDatabases\0")
    assert request[position - 1] == 0x08 and request[position + 20] == 0
    assert b"nameOnly\0\x01" in request


def test_modern_servers_get_current_messages():
    fake = FakeMongo(wire=MODERN)
    check(fake)
    assert fake.opcodes == [mongo_wire.OP_QUERY, mongo_wire.OP_MSG, mongo_wire.OP_MSG]


def test_old_servers_get_old_messages():
    fake = FakeMongo(wire=OLD, dbs=("customers",))
    svc = check(fake)
    assert fake.opcodes == [mongo_wire.OP_QUERY] * 3
    assert svc.findings == [MONGODB_NO_AUTH]


def test_database_names_are_never_kept():
    # Old servers ignore the filter and do send names.
    fields, complete = decode_doc(bson({}, db_list("customers", "payroll"), ok()))
    assert complete and fields == {"databases": None, "ok": 1.0}
    svc = check(FakeMongo(wire=OLD, dbs=("customers", "payroll")))
    assert "customers" not in json.dumps(svc.to_dict())


@pytest.mark.parametrize("replies", [
    {"isMaster": bson({"hello": "not mongo"}, ok())},
    {"isMaster": bson({"maxWireVersion": 17}, ok(0.0))},
    {"isMaster": bson({"maxWireVersion": "seventeen"}, ok())},
    {"listDatabases": bson({"databases": 1}, ok(0.0))},
    {"listDatabases": bson({}, ok())},  # says ok but gives no list
])
def test_anything_short_of_proof_is_not_a_finding(replies):
    assert check(FakeMongo(replies=replies)).findings == []


def test_stops_at_once_if_it_is_not_mongodb():
    fake = FakeMongo(replies={"isMaster": bson({"hello": "not mongo"}, ok())})
    check(fake)
    assert fake.commands == ["isMaster"]


def test_cut_off_list_is_not_proof():
    big = bson({"padding": "A" * 10_000}, db_list(), ok())
    assert check(FakeMongo(replies={"listDatabases": big})).findings == []


def test_broken_build_info_keeps_the_finding():
    svc = check(FakeMongo(replies={"buildInfo": b"garbage"}))
    assert svc.findings == [MONGODB_NO_AUTH]
    assert (svc.product, svc.version) == ("MongoDB", "")


def test_long_build_info_still_gives_version():
    long_info = bson({"version": "7.0.2", "buildEnvironment": "x" * 20_000}, ok())
    assert check(FakeMongo(replies={"buildInfo": long_info})).version == "7.0.2"


def test_odd_version_text_is_ignored():
    svc = check(FakeMongo(version="[red]$(evil)"))
    assert svc.version == "" and svc.cpes == []


def test_only_mongodb_services_are_checked():
    fake = FakeMongo()
    with fake:
        svc = Service("127.0.0.1", fake.port, "tcp", "open", name="ftp-data")
        asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=1.0))
    assert fake.commands == []


# --- hostile replies ----------------------------------------------------------


def raw_server(data: bytes) -> Service:
    async def handler(reader, writer):
        try:
            await reader.read(1024)
            writer.write(data)
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    async def main():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        svc = Service("127.0.0.1", server.sockets[0].getsockname()[1], "tcp", "open",
                      name="mongodb")
        async with server:
            await misconfig._run_checks([svc], concurrency=1, timeout=0.5)
            server.close()
        return svc

    return asyncio.run(main())


@pytest.mark.parametrize("data", [
    b"",
    b"hello there",
    b"HTTP/1.0 400 Bad Request\r\n\r\n",
    struct.pack("<iiii", -5, 0, 1, 1),
    struct.pack("<iiii", 0, 0, 1, 1),
    struct.pack("<iiii", 2_000_000_000, 0, 1, 1),
    struct.pack("<iiii", 100, 0, 1, 9999) + b"A" * 84,
    struct.pack("<iiii", 100, 0, 7, 1) + b"A" * 84,  # answers a different request
    struct.pack("<iiii", 100, 0, 1, 1) + b"A" * 10,  # shorter than it says
])
def test_broken_replies_give_no_finding(data):
    assert raw_server(data).findings == []


@pytest.mark.parametrize("doc", [
    b"",
    b"\x00\x00\x00",
    struct.pack("<i", -1) + b"\x00",
    struct.pack("<i", 3) + b"\x00",
    struct.pack("<i", 8) + b"\x02x\0\xff\xff\xff\xff\x00",  # negative string length
    struct.pack("<i", 9) + b"\x02x\0\x7f\xff\xff\x7f\x00",  # string past the end
    struct.pack("<i", 7) + b"\xeex\0\x00",                  # unknown type
    encode_doc({"a": 1})[:-1] + b"\x01",                    # not terminated
])
def test_malformed_documents_raise_value_error(doc):
    with pytest.raises(ValueError):
        decode_doc(doc)


def test_damaged_documents_never_crash():
    # Only ValueError is allowed out, whatever the damage.
    good = bson({"version": "4.4.6", "n": 7, "flag": True}, db_list("a", "b"), ok())
    rng = random.Random(1234)
    for i in range(len(good)):
        for value in (0x00, 0x7F, 0xFF, rng.randrange(256)):
            damaged = bytearray(good)
            damaged[i] = value
            try:
                decode_doc(bytes(damaged))
            except ValueError:
                pass
    for cut in range(len(good)):
        try:
            decode_doc(good[:cut])
        except ValueError:
            pass


def test_encode_and_decode_round_trip():
    doc = {"s": "héllo", "n": -3, "t": True, "f": False}
    assert decode_doc(encode_doc(doc)) == (doc, True)


def test_encoder_refuses_unknown_types():
    with pytest.raises(TypeError):
        encode_doc({"x": 1.5})


# --- end to end ---------------------------------------------------------------


def test_mongodb_http_answer_is_not_a_web_server():
    banner = "HTTP/1.0 200 OK\nIt looks like you are trying to access MongoDB over HTTP"
    fp = identify(banner)
    assert (fp.name, fp.product) == ("mongodb", "MongoDB")


def run_cli(fake: FakeMongo) -> dict:
    with fake:
        result = CliRunner().invoke(
            app, ["scan", "127.0.0.1", "-p", str(fake.port), "--karen-mode", "--json", "-t", "5"]
        )
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)[0]


def test_full_scan_finds_open_mongodb_on_unusual_port():
    svc = run_cli(FakeMongo(version="3.4.24", wire=OLD))
    assert (svc["name"], svc["product"], svc["version"]) == ("mongodb", "MongoDB", "3.4.24")
    assert [f["check"] for f in svc["findings"]] == ["mongodb-no-auth"]


def test_full_scan_with_login_required_reports_nothing():
    svc = run_cli(FakeMongo(auth=True))
    assert (svc["name"], svc["product"]) == ("mongodb", "MongoDB")
    assert svc["findings"] == []
