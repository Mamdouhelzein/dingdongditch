"""Karen mode: read each TLS port's certificate and flag the usual problems.

Certificates come from the target, so their text is cleaned like banners, and
a certificate we can't parse is skipped rather than trusted.
"""

from __future__ import annotations

import asyncio
import contextlib
import warnings
from collections.abc import Iterable
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from dingdongditch import probes
from dingdongditch.nmap_parser import Service

WEAK_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1"}
WEAK_HASHES = {"md5", "sha1"}
MAX_NAMES = 10  # certificates can list hundreds of alternative names


async def fetch_cert(
    host: str, port: int, timeout: float = probes.TIMEOUT
) -> tuple[bytes, str]:
    """Do a TLS handshake; return (certificate in DER form, TLS version), empty on failure."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=probes.tls_context()), timeout
        )
    except (*probes.TIMEOUT_ERRORS, OSError):
        return b"", ""
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        return ssl_object.getpeercert(binary_form=True) or b"", ssl_object.version() or ""
    finally:
        writer.close()
        with contextlib.suppress(*probes.TIMEOUT_ERRORS, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


def _clean(text: object) -> str:
    return probes.clean_banner(str(text).encode())


def _name(name: x509.Name) -> str:
    """The most readable part of a certificate name: common name, else organisation."""
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attributes = name.get_attributes_for_oid(oid)
        if attributes:
            return _clean(attributes[0].value)
    return ""


def _alt_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        return []
    return [_clean(n) for n in san.get_values_for_type(x509.DNSName)[:MAX_NAMES]]


def _signature(cert: x509.Certificate) -> str:
    try:
        algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return ""
    return algorithm.name if algorithm else ""  # None for ed25519, which has no separate hash


def describe_cert(der: bytes, tls_version: str = "", now: datetime | None = None) -> dict:
    """Turn a DER certificate into plain facts plus a list of problems ({} if unreadable)."""
    try:
        with warnings.catch_warnings():
            # Sloppy certificates are what we're looking for, not worth console noise.
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            cert = x509.load_der_x509_certificate(der)
        # Names are parsed on demand, so a hostile certificate can fail here too.
        subject, issuer = _name(cert.subject), _name(cert.issuer)
        self_signed = cert.subject == cert.issuer
        not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
    except ValueError:
        return {}
    now = now or datetime.now(timezone.utc)
    signature = _signature(cert)

    problems = []
    if now > not_after:
        problems.append("expired")
    elif now < not_before:
        problems.append("not yet valid")
    if self_signed:
        problems.append("self-signed")
    if signature in WEAK_HASHES:
        problems.append(f"weak signature ({signature})")
    if tls_version in WEAK_TLS_VERSIONS:
        problems.append(f"old TLS ({tls_version})")

    return {
        "subject": subject,
        "issuer": issuer,
        "alt_names": _alt_names(cert),
        "not_before": not_before.date().isoformat(),
        "not_after": not_after.date().isoformat(),
        "self_signed": self_signed,
        "signature": signature,
        "tls_version": tls_version,
        "problems": problems,
    }


async def _add_tls_info(services: list[Service], concurrency: int, timeout: float) -> None:
    sem = asyncio.Semaphore(concurrency)

    async def one(svc: Service) -> None:
        async with sem:
            der, version = await fetch_cert(svc.host, svc.port, timeout)
        if der:
            svc.tls_cert = describe_cert(der, version)

    await asyncio.gather(*(one(s) for s in services if s.tls))


def add_tls_info(
    services: Iterable[Service],
    concurrency: int = probes.DEFAULT_CONCURRENCY,
    timeout: float = probes.TIMEOUT,
) -> list[Service]:
    """Fill in `tls_cert` for every service that spoke TLS."""
    services = list(services)
    asyncio.run(_add_tls_info(services, concurrency, timeout))
    return services
