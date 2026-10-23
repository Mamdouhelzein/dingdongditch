"""Parse nmap XML output (`nmap -sV -oX ...`) into a list of open services."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO


@dataclass
class Service:
    host: str
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Human-readable 'product version', falling back to the service name."""
        text = " ".join(p for p in (self.product, self.version) if p)
        return text or self.name or "unknown"

    def to_dict(self) -> dict:
        return asdict(self)


def _host_address(host: ET.Element) -> str:
    # Prefer IPv4, then IPv6, then whatever address is present.
    addrs = host.findall("address")
    for wanted in ("ipv4", "ipv6"):
        for a in addrs:
            if a.get("addrtype") == wanted:
                return a.get("addr", "")
    return addrs[0].get("addr", "") if addrs else ""


def parse_nmap_xml(source: str | Path | IO, only_open: bool = True) -> list[Service]:
    """Return the services found in an nmap XML report.

    `source` can be a path or a file-like object (e.g. sys.stdin).
    """
    try:
        root = ET.parse(source).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Not a valid nmap XML file: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValueError("Not an nmap XML report (missing <nmaprun> root). Use `nmap -oX`.")

    services: list[Service] = []
    for host in root.iter("host"):
        addr = _host_address(host)
        for port in host.iter("port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if only_open and state != "open":
                continue
            svc_el = port.find("service")
            svc = svc_el if svc_el is not None else ET.Element("service")
            services.append(
                Service(
                    host=addr,
                    port=int(port.get("portid", 0)),
                    protocol=port.get("protocol", ""),
                    state=state,
                    name=svc.get("name", ""),
                    product=svc.get("product", ""),
                    version=svc.get("version", ""),
                    extrainfo=svc.get("extrainfo", ""),
                    cpes=[c.text.strip() for c in svc.findall("cpe") if c.text],
                )
            )
    return services
