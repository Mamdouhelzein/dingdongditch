import asyncio
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from dingdongditch import own_scanner, tls_info
from dingdongditch.cli import app
from dingdongditch.nmap_parser import Service
from dingdongditch.tls_info import describe_cert

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
KEY = ec.generate_private_key(ec.SECP256R1())


def _x509_name(cn: str, org: str | None = None) -> x509.Name:
    parts = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []
    if org:
        parts.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(parts)


def make_cert(cn="lab.local", issuer=None, org=None, days=(-30, 30), names=()) -> bytes:
    """A certificate in DER form, valid `days` around NOW. Self-signed unless `issuer`."""
    subject = _x509_name(cn, org)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_x509_name(issuer) if issuer else subject)
        .public_key(KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + timedelta(days=days[0]))
        .not_valid_after(NOW + timedelta(days=days[1]))
    )
    if names:
        san = x509.SubjectAlternativeName([x509.DNSName(n) for n in names])
        builder = builder.add_extension(san, critical=False)
    cert = builder.sign(KEY, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_plain_facts():
    der = make_cert("jenkins.lab", issuer="Lab CA", names=["jenkins.lab", "ci.lab"])
    assert describe_cert(der, "TLSv1.3", NOW) == {
        "subject": "jenkins.lab",
        "issuer": "Lab CA",
        "alt_names": ["jenkins.lab", "ci.lab"],
        "not_before": "2026-05-02",
        "not_after": "2026-07-01",
        "self_signed": False,
        "signature": "sha256",
        "tls_version": "TLSv1.3",
        "problems": [],
    }


@pytest.mark.parametrize("kwargs, version, problem", [
    ({"issuer": "CA", "days": (-30, -1)}, "TLSv1.3", "expired"),
    ({"issuer": "CA", "days": (1, 30)}, "TLSv1.3", "not yet valid"),
    ({}, "TLSv1.3", "self-signed"),
    ({"issuer": "CA"}, "TLSv1", "old TLS (TLSv1)"),
    ({"issuer": "CA"}, "TLSv1.1", "old TLS (TLSv1.1)"),
])
def test_problems(kwargs, version, problem):
    assert describe_cert(make_cert(**kwargs), version, NOW)["problems"] == [problem]


@pytest.mark.parametrize("name", ["sha1", "md5"])
def test_weak_signature(monkeypatch, name):
    # cryptography refuses to create such certificates, so fake the name it reads.
    monkeypatch.setattr(tls_info, "_signature", lambda cert: name)
    info = describe_cert(make_cert(issuer="CA"), "TLSv1.3", NOW)
    assert info["problems"] == [f"weak signature ({name})"]
    assert info["signature"] == name


def test_several_problems_at_once():
    problems = describe_cert(make_cert(days=(-30, -1)), "TLSv1", NOW)["problems"]
    assert problems == ["expired", "self-signed", "old TLS (TLSv1)"]


def test_falls_back_to_organisation():
    info = describe_cert(make_cert(cn="", org="Acme Ltd", issuer="CA"), now=NOW)
    assert info["subject"] == "Acme Ltd"


def test_no_name_at_all():
    assert describe_cert(make_cert(cn="", issuer="CA"), now=NOW)["subject"] == ""


def test_alt_names_are_capped():
    names = [f"h{i}.lab" for i in range(50)]
    info = describe_cert(make_cert(names=names), now=NOW)
    assert len(info["alt_names"]) == tls_info.MAX_NAMES


def test_text_from_the_certificate_is_cleaned():
    assert describe_cert(make_cert("\x1b[31mevil"), now=NOW)["subject"] == "\\x1b[31mevil"


@pytest.mark.parametrize("junk", [b"", b"not a certificate", b"\x30\x82\xff\xff" + b"A" * 50])
def test_unreadable_certificate_is_skipped(junk):
    assert describe_cert(junk) == {}


def test_damaged_certificate_does_not_crash():
    # Flip bytes all over a real certificate: it may parse or not, but must never raise.
    der = make_cert(issuer="CA", names=["a.lab"])
    for i in range(len(der)):
        damaged = bytearray(der)
        damaged[i] ^= 0xFF
        describe_cert(bytes(damaged), now=NOW)


# --- reading from a fake TLS server -----------------------------------------


def _server_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(FIXTURES / "test_only_cert.pem", FIXTURES / "test_only_key.pem")
    return ctx


def run_against(tls: bool, svc_tls: bool = True) -> Service:
    async def handler(reader, writer):
        await reader.read(100)
        writer.close()

    async def main():
        ctx = _server_context() if tls else None
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        svc = Service("127.0.0.1", port, "tcp", "open", tls=svc_tls)
        async with server:
            await tls_info._add_tls_info([svc], concurrency=5, timeout=2.0)
        return svc

    return asyncio.run(main())


def test_reads_certificate_from_tls_server():
    cert = run_against(tls=True).tls_cert
    assert cert["subject"] == "dingdongditch-test"
    assert cert["self_signed"] is True and "self-signed" in cert["problems"]
    assert cert["tls_version"].startswith("TLSv1")


def test_plain_service_leaves_cert_empty():
    assert run_against(tls=False).tls_cert == {}


def test_non_tls_services_are_not_contacted():
    assert run_against(tls=True, svc_tls=False).tls_cert == {}


# --- wiring -------------------------------------------------------------------


def test_only_karen_mode_reads_certificates(monkeypatch):
    calls = []
    monkeypatch.setattr(own_scanner.connect_scan, "scan", lambda *a, **k: [])
    monkeypatch.setattr(own_scanner.probes, "add_banners", lambda s, **k: s)
    monkeypatch.setattr(own_scanner.http_info, "add_http_info", lambda s, **k: s)
    monkeypatch.setattr(tls_info, "add_tls_info", lambda s, **k: calls.append(1) or s)

    own_scanner.run_scan(["127.0.0.1"], [443])
    assert calls == []
    own_scanner.run_scan(["127.0.0.1"], [443], karen_mode=True)
    assert calls == [1]


def test_table_shows_cert_and_escapes_it(monkeypatch):
    cert = describe_cert(make_cert("[b]x[/b]", days=(-30, -1)), "TLSv1.3", NOW)
    svc = Service("10.0.0.5", 443, "tcp", "open", name="https", tls=True, tls_cert=cert)
    monkeypatch.setattr(own_scanner, "run_scan", lambda *a, **k: [svc])
    result = CliRunner().invoke(app, ["scan", "10.0.0.5", "-p", "443"])
    assert result.exit_code == 0, result.output
    assert "[b]x[/b]" in result.stdout
    assert "expired" in result.stdout and "self-signed" in result.stdout
