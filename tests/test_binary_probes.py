import struct

import pytest
from test_probes import answers, grab_as, karen_grab, recording, run_with_server

from dingdongditch import binary_probes, probes
from dingdongditch.binary_probes import DNS_ID, DNS_VERSION_QUERY, decode_dns
from dingdongditch.fingerprints import identify
from dingdongditch.probes import to_text

# --- DNS ------------------------------------------------------------------


def dns_reply(*txt: bytes, error: int = 0, ident: int = DNS_ID) -> bytes:
    """A DNS server's TCP answer to our version.bind question, as BIND builds it."""
    question = DNS_VERSION_QUERY[14:]  # name, type and class, echoed back
    answers_ = b""
    if txt:
        rdata = b"".join(bytes([len(t)]) + t for t in txt)
        # c0 0c: "the name at byte 12", i.e. version.bind from the question
        answers_ = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, len(rdata)) + rdata
    header = struct.pack(">HHHHHH", ident, 0x8400 | error, 1, len(txt) and 1, 0, 0)
    msg = header + question + answers_
    return struct.pack(">H", len(msg)) + msg


def test_dns_question_is_version_bind_in_chaos_class():
    assert DNS_VERSION_QUERY == (
        b"\x00\x1e" b"dd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00" b"\x00\x10\x00\x03"
    )


@pytest.mark.parametrize("reply, expected", [
    (dns_reply(b"9.4.2"), "version.bind: 9.4.2"),
    (dns_reply(b"dnsmasq-", b"2.80"), "version.bind: dnsmasq-2.80"),  # several strings
    (dns_reply(b"none\r\nSSH-2.0-OpenSSH_9.6"), "version.bind: none SSH-2.0-OpenSSH_9.6"),
    (dns_reply(error=5), "version.bind: no answer (refused)"),
    (dns_reply(error=4), "version.bind: no answer (not implemented)"),
    (dns_reply(error=9), "version.bind: no answer (code 9)"),
    (dns_reply(b"9.4.2")[:-3], None),  # cut short
    (dns_reply(b"9.4.2", ident=0x1234), None),  # not an answer to us
    (DNS_VERSION_QUERY, None),  # a question, not an answer
    (b"SSH-2.0-OpenSSH_7.4\r\n", None),
    (b"", None),
])
def test_decode_dns(reply, expected):
    assert decode_dns(reply) == expected


def test_broken_answer_section_counts_as_no_answer():
    reply = bytearray(dns_reply())
    reply[2 + 7] = 1  # claim an answer that isn't there
    assert decode_dns(bytes(reply)) == "version.bind: no answer (no record)"


@pytest.mark.parametrize("txt, product, version, extra, cpe", [
    (b"9.4.2", "ISC BIND", "9.4.2", "", "cpe:/a:isc:bind:9.4.2"),
    (b"9.11.5-P4-5.1+deb10u5-Debian", "ISC BIND", "9.11.5-P4", "5.1+deb10u5-Debian",
     "cpe:/a:isc:bind:9.11.5-P4"),
    (b"9.18.28-0ubuntu0.22.04.1-Ubuntu", "ISC BIND", "9.18.28", "0ubuntu0.22.04.1-Ubuntu",
     "cpe:/a:isc:bind:9.18.28"),
    (b"dnsmasq-2.80", "dnsmasq", "2.80", "", "cpe:/a:thekelleys:dnsmasq:2.80"),
    (b"unbound 1.17.1", "Unbound", "1.17.1", "", "cpe:/a:nlnetlabs:unbound:1.17.1"),
    (b"PowerDNS Authoritative Server 4.8.3 (built Oct 2 2023)",
     "PowerDNS Authoritative Server", "4.8.3", "", "cpe:/a:powerdns:authoritative:4.8.3"),
    (b"none of your business", "", "", "", ""),
])
def test_dns_fingerprints(txt, product, version, extra, cpe):
    fp = identify(to_text(dns_reply(txt)))
    assert (fp.name, fp.product, fp.version, fp.extrainfo) == ("domain", product, version, extra)
    assert fp.cpes == ([cpe] if cpe else [])


def test_refused_is_still_dns():
    fp = identify(to_text(dns_reply(error=5)))
    assert (fp.name, fp.product, fp.cpes) == ("domain", "", [])


def test_dns_port_asks_version_bind_straight_away(monkeypatch):
    monkeypatch.setattr(probes, "LISTEN_TIMEOUT", 30)  # would be slow if we listened first
    banner = run_with_server(
        answers(DNS_VERSION_QUERY, dns_reply(b"9.4.2")), grab_as(monkeypatch, "domain"),
    )
    assert banner.text == "version.bind: 9.4.2"


def test_text_answers_are_left_alone():
    assert binary_probes.describe(b"220 (vsFTPd 2.3.4)\r\n") is None
    assert to_text(b"220 (vsFTPd 2.3.4)\r\n") == "220 (vsFTPd 2.3.4)"


def test_unknown_binary_still_escaped():
    assert to_text(b"\x00\x01\x1b[31m") == "\\x00\\x01\\x1b[31m"


# --- PostgreSQL -------------------------------------------------------------


def pg_error(**fields: str) -> bytes:
    """A PostgreSQL ErrorResponse: 'E', length, then type letter + text + NUL per field."""
    body = b"".join(k.encode() + v.encode() + b"\0" for k, v in fields.items()) + b"\0"
    return b"E" + struct.pack(">I", len(body) + 4) + body


REFUSED_4_0 = {
    "S": "FATAL", "C": "0A000",
    "M": "unsupported frontend protocol 4.0: server supports 1.0 to 3.0",
    "F": "postmaster.c", "L": "1497", "R": "ProcessStartupPacket",
}


def test_postgres_question_is_protocol_4():
    assert binary_probes.PG_STARTUP == b"\x00\x00\x00\x08\x00\x04\x00\x00"


@pytest.mark.parametrize("reply, expected", [
    (pg_error(**REFUSED_4_0),
     "postgresql error: FATAL 0A000: unsupported frontend protocol 4.0: server supports 1.0 "
     "to 3.0 (postmaster.c:1497 ProcessStartupPacket)"),
    (pg_error(S="FATAL", V="FATAL", C="0A000", M="no"), "postgresql error: FATAL 0A000: no"),
    (pg_error(S="FATAL", C="0A000", M="line\nbreak"), "postgresql error: FATAL 0A000: line break"),
    (pg_error(**REFUSED_4_0)[:-1], None),  # cut short
    (pg_error(S="FATAL", C="0A000"), None),  # no message
    (b"ERROR\r\n", None),  # memcached's answer to a blank line starts with E too
    (b"E", None),
])
def test_decode_postgres(reply, expected):
    assert binary_probes.decode_postgres(reply) == expected


def pg_fingerprint(file: str, line: str):
    return identify(to_text(pg_error(**{**REFUSED_4_0, "F": file, "L": line})))


@pytest.mark.parametrize("file, line, version, extra", [
    ("postmaster.c", "1497", "8.3", "one of 8.3.0-8.3.7"),  # Metasploitable 2's 8.3.1
    ("backend_startup.c", "698", "17.10", ""),  # only one release has it
    ("backend_startup.c", "707", "", "one of 17.11, 18.0-18.3"),  # two branches
    ("postmaster.c", "99999", "", ""),  # patched or unknown: still PostgreSQL
    ("nowhere.c", "1497", "", ""),
])
def test_postgres_version_from_source_line(file, line, version, extra):
    fp = pg_fingerprint(file, line)
    assert (fp.name, fp.product, fp.version, fp.extrainfo) == (
        "postgresql", "PostgreSQL", version, extra
    )
    assert fp.cpes == ["cpe:/a:postgresql:postgresql" + (f":{version}" if version else "")]


def test_postgres_without_source_line_is_still_postgres():
    fp = identify(to_text(pg_error(S="FATAL", C="0A000", M="unsupported frontend protocol")))
    assert (fp.name, fp.product, fp.version) == ("postgresql", "PostgreSQL", "")


def test_postgres_port_asks_straight_away(monkeypatch):
    monkeypatch.setattr(probes, "LISTEN_TIMEOUT", 30)
    banner = run_with_server(
        answers(binary_probes.PG_STARTUP, pg_error(**REFUSED_4_0)),
        grab_as(monkeypatch, "postgresql"),
    )
    assert banner.text.startswith("postgresql error: FATAL 0A000")


def test_karen_mode_finds_postgres_on_odd_port(monkeypatch):
    def postgres_only(request):
        return pg_error(**REFUSED_4_0) if request == binary_probes.PG_STARTUP else b""

    handler, requests = recording(postgres_only)
    banner = run_with_server(handler, karen_grab(monkeypatch))
    assert identify(banner.text).product == "PostgreSQL"
    assert requests[-1] == binary_probes.PG_STARTUP
