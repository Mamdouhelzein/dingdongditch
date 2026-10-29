"""The built-in engine: find open ports, ask each what it is, fingerprint the answer.

Returns the same Service objects as the nmap engine, so the rest of the
pipeline doesn't care which one ran.
"""

from __future__ import annotations

from collections.abc import Iterable

from dingdongditch import connect_scan, probes
from dingdongditch.fingerprints import fingerprint
from dingdongditch.nmap_parser import Service
from dingdongditch.ports import PROFILES, parse_ports
from dingdongditch.targets import parse_targets


def resolve(
    targets: str | Iterable[str],
    profile: str = "default",
    ports: str | None = None,
    no_chill: bool = False,
) -> tuple[list[str], list[int]]:
    """Work out which IPs and ports to scan. Custom ports win over profiles."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. Choose from: {', '.join(PROFILES)}")
    hosts = parse_targets(targets)
    if ports:
        port_list = parse_ports(ports)
    else:
        port_list = PROFILES["full" if no_chill else profile]
    return hosts, port_list


def run_scan(
    hosts: list[str],
    ports: list[int],
    timeout: float = connect_scan.DEFAULT_TIMEOUT,
    concurrency: int = connect_scan.DEFAULT_CONCURRENCY,
) -> list[Service]:
    """Scan `hosts` x `ports` and return the identified open services."""
    services = connect_scan.scan(hosts, ports, timeout=timeout, concurrency=concurrency)
    services = probes.add_banners(
        services, concurrency=min(concurrency, probes.DEFAULT_CONCURRENCY)
    )
    return fingerprint(services)
