"""The built-in engine: find open ports, ask each what it is, fingerprint the answer.

Returns the same Service objects as the nmap engine, so the rest of the
pipeline doesn't care which one ran.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from dingdongditch import connect_scan, http_info, probes, tls_info
from dingdongditch.fingerprints import fingerprint
from dingdongditch.nmap_parser import Service
from dingdongditch.ports import PROFILES, parse_ports
from dingdongditch.targets import parse_targets


def resolve(
    targets: str | Iterable[str],
    profile: str = "default",
    ports: str | None = None,
    karen_mode: bool = False,
) -> tuple[list[str], list[int]]:
    """Work out which IPs and ports to scan. Custom ports win over profiles."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. Choose from: {', '.join(PROFILES)}")
    hosts = parse_targets(targets)
    if ports:
        port_list = parse_ports(ports)
    else:
        port_list = PROFILES["full" if karen_mode else profile]
    return hosts, port_list


def run_scan(
    hosts: list[str],
    ports: list[int],
    timeout: float = connect_scan.DEFAULT_TIMEOUT,
    concurrency: int = connect_scan.DEFAULT_CONCURRENCY,
    on_result: Callable[[], None] | None = None,
    on_slowdown: Callable[[int], None] | None = None,
    on_identify: Callable[[int], None] | None = None,
    karen_mode: bool = False,
) -> list[Service]:
    """Scan `hosts` x `ports` and return the identified open services.

    `karen_mode` sends extra probes to ports the first probe didn't identify,
    fetches web ports' home pages for their title, headers and app, and reads
    TLS certificates.
    Callbacks (for progress display): `on_result()` after each port check,
    `on_slowdown(n)` if the OS forces fewer connections, and
    `on_identify(n_open)` when banner grabbing starts.
    """
    services = connect_scan.scan(
        hosts, ports, timeout=timeout, concurrency=concurrency,
        on_result=on_result, on_slowdown=on_slowdown,
    )
    if on_identify:
        on_identify(len(services))
    grab_concurrency = min(concurrency, probes.DEFAULT_CONCURRENCY)
    services = probes.add_banners(services, concurrency=grab_concurrency, karen_mode=karen_mode)
    services = fingerprint(services)
    if karen_mode:
        services = http_info.add_http_info(services, concurrency=grab_concurrency)
        services = tls_info.add_tls_info(services, concurrency=grab_concurrency)
    return services
