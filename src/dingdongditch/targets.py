"""Turn what the user typed (IPs, hostnames, subnets) into a list of IPs to scan."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable

# Refuse anything bigger than a /16 so a typo can't start a huge scan.
MAX_HOSTS = 65_536


def _expand_network(token: str, max_hosts: int) -> list[str]:
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {token!r}") from exc
    if net.num_addresses > max_hosts:
        raise ValueError(
            f"Subnet {token} has {net.num_addresses:,} addresses (limit {max_hosts:,})."
        )
    # /31, /32 (and IPv6 /127, /128) have no network/broadcast address to skip.
    hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
    return [str(ip) for ip in hosts]


def _resolve(hostname: str) -> str:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"Can't resolve hostname: {hostname!r}") from exc
    addrs = [info[4][0] for info in infos]
    # Prefer IPv4, like the nmap parser does.
    ipv4 = [a for a in addrs if ":" not in a]
    return (ipv4 or addrs)[0]


def split_targets(specs: str | Iterable[str]) -> list[str]:
    """Split one or more target strings on commas and spaces; reject option-like ones."""
    if isinstance(specs, str):
        specs = [specs]
    tokens = [t for spec in specs for t in re.split(r"[,\s]+", spec) if t]
    if not tokens:
        raise ValueError("No targets given.")
    for token in tokens:
        if token.startswith("-"):
            raise ValueError(f"Invalid target: {token!r}")
    return tokens


def parse_targets(specs: str | Iterable[str], max_hosts: int = MAX_HOSTS) -> list[str]:
    """Parse targets like '10.0.0.1,10.0.0.2', '172.17.0.0/24' or 'localhost'.

    `specs` is one string or several (e.g. the CLI arguments). Commas and spaces
    both separate targets. Returns unique IPs in the order they were given.
    """
    tokens = split_targets(specs)

    ips: dict[str, None] = {}  # dict keeps insertion order and drops duplicates
    for token in tokens:
        if "/" in token:
            ips.update(dict.fromkeys(_expand_network(token, max_hosts)))
        else:
            try:
                ips[str(ipaddress.ip_address(token))] = None
            except ValueError:
                ips[_resolve(token)] = None
        if len(ips) > max_hosts:
            raise ValueError(f"Too many targets: more than {max_hosts:,} addresses.")
    return list(ips)
