import struct

import pytest
from test_probes import answers, grab_as, run_with_server

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
