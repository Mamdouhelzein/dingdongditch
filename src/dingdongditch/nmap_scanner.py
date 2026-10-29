"""Run nmap service/version detection and return the parsed services."""

from __future__ import annotations

import io
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

from dingdongditch.nmap_parser import Service, parse_nmap_xml
from dingdongditch.targets import split_targets

# Scan profiles: how much of the network to look at, and how hard.
PROFILES: dict[str, list[str]] = {
    "quick": ["--top-ports", "100", "-T4"],   # fastest, most common ports
    "default": ["--top-ports", "1000"],       # nmap's default port set
    "full": ["-p-", "-T4"],                   # all 65,535 TCP ports (slow)
}


class NmapNotFoundError(RuntimeError):
    pass


def find_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotFoundError(
            "nmap is not installed or not on your PATH.\n"
            "  macOS:  brew install nmap\n"
            "  Linux:  sudo apt install nmap\n"
            "  Windows: https://nmap.org/download.html"
        )
    return path


def build_command(
    targets: str | Iterable[str],
    profile: str = "default",
    ports: str | None = None,
    nmap_path: str = "nmap",
    karen_mode: bool = False,
) -> list[str]:
    """Build the nmap command. Output is XML on stdout (-oX -).

    `--karen-mode` scans all ports (unless `ports` is given) with every version probe.
    """
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. Choose from: {', '.join(PROFILES)}")
    # Also stops a "target" from being interpreted as an nmap option.
    target_list = split_targets(targets)

    cmd = [nmap_path, "-sV", "--open", "-oX", "-"]
    cmd += ["-p", ports] if ports else PROFILES["full" if karen_mode else profile]
    if karen_mode:
        cmd.append("--version-all")
    cmd += target_list
    return cmd


def run_scan(
    targets: str | Iterable[str],
    profile: str = "default",
    ports: str | None = None,
    save_xml: Path | None = None,
    timeout: int | None = None,
    karen_mode: bool = False,
) -> list[Service]:
    """Scan `targets` with nmap -sV and return the open services."""
    cmd = build_command(targets, profile, ports, nmap_path=find_nmap(), karen_mode=karen_mode)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        msg = result.stderr.strip() or f"nmap exited with code {result.returncode}"
        raise RuntimeError(msg)

    if save_xml:
        save_xml.write_text(result.stdout)
    return parse_nmap_xml(io.StringIO(result.stdout))
