"""Karen mode: guess each host's OS from clues in what its services already said.

No extra traffic. It's only a guess (banners can lie, and containers don't show
the host's OS), so every clue is kept in `os_evidence` to show where it came from.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from dingdongditch.nmap_parser import Service


@dataclass(frozen=True)
class Clue:
    distro: str          # "Debian", or the family itself when that's all we know
    family: str          # "Linux", "Windows", ...
    version: str = ""
    port: int = 0
    service: str = ""

    @property
    def os(self) -> str:
        return f"{self.distro} {self.version}".strip()


def _rule(regex: str, distro: str, family: str = "Linux") -> tuple[re.Pattern[str], str, str]:
    return re.compile(regex, re.MULTILINE), distro, family


# Most specific first; each service gives one clue, from the first rule that matches.
RULES = [
    _rule(r"\+deb(?P<version>\d+)u\d+", "Debian"),  # 10+deb9u7 is Debian 9's package
    _rule(r"\bDebian\b", "Debian"),
    _rule(r"\bUbuntu\b|\dubuntu\d", "Ubuntu"),
    _rule(r"\bCentOS\b", "CentOS"),
    _rule(r"\bRed Hat\b", "Red Hat"),
    _rule(r"\bFedora\b", "Fedora"),
    _rule(r"\(Amazon\)|\bAmazon Linux\b", "Amazon Linux"),
    _rule(r"\bSUSE\b", "SUSE"),
    _rule(r"\bAlpine\b", "Alpine"),
    _rule(r"\bFreeBSD\b", "FreeBSD", "BSD"),
    _rule(r"\bOpenBSD\b", "OpenBSD", "BSD"),
    _rule(r"\(Win(?:32|64)\)|OpenSSH_for_Windows|Microsoft-IIS|Microsoft-HTTPAPI"
          r"|Microsoft FTP Service|Microsoft ESMTP|^(?:X-Powered-By: )?ASP\.NET",
          "Windows", "Windows"),
    # Redis INFO server has an os: line.
    _rule(r"^os:Linux\b", "Linux"),
    _rule(r"^os:Darwin\b", "macOS", "macOS"),
    _rule(r"^os:Windows\b", "Windows", "Windows"),
]

# Open ports that strongly suggest an OS even when the service says nothing.
PORT_HINTS = {"msrpc": ("Windows", "Windows"), "ms-wbt-server": ("Windows", "Windows")}


def clue_from(svc: Service) -> Clue | None:
    """The best OS clue from one service, or None."""
    where = {"port": svc.port, "service": svc.name}
    text = "\n".join([svc.banner, *svc.http_headers.values()])
    for pattern, distro, family in RULES:
        m = pattern.search(text)
        if m:
            return Clue(distro, family, m.groupdict().get("version") or "", **where)
    if svc.name in PORT_HINTS:
        distro, family = PORT_HINTS[svc.name]
        return Clue(distro, family, **where)
    return None


def _most_common(values: Iterable[str]) -> str:
    """Most frequent value; ties go to the one seen first (clues are in port order)."""
    return Counter(values).most_common(1)[0][0]


def guess_os(clues: list[Clue]) -> str:
    """One OS name from a host's clues: most-voted family, then its most specific distro."""
    family = _most_common(c.family for c in clues)
    in_family = [c for c in clues if c.family == family]
    # "Debian" says more than a bare "Linux", however many ports said Linux.
    named = [c for c in in_family if c.distro != family] or in_family
    distro = _most_common(c.distro for c in named)
    versions = [c.version for c in named if c.distro == distro and c.version]
    return f"{distro} {_most_common(versions)}" if versions else distro


def add_os_guess(services: Iterable[Service]) -> list[Service]:
    """Set `os_guess` and `os_evidence` on every service, one guess per host."""
    services = list(services)
    by_host: dict[str, list[Service]] = {}
    for svc in services:
        by_host.setdefault(svc.host, []).append(svc)

    for host_services in by_host.values():
        ordered = sorted(host_services, key=lambda s: s.port)
        clues = [c for c in map(clue_from, ordered) if c]
        if not clues:
            continue
        guess = guess_os(clues)
        evidence = [f"port {c.port} ({c.service or 'unknown'}): {c.os}" for c in clues]
        for svc in host_services:
            svc.os_guess, svc.os_evidence = guess, evidence
    return services
