"""dingdongditch command-line interface."""

from __future__ import annotations

import errno
import json
import subprocess
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from dingdongditch import __version__, nmap_scanner, own_scanner
from dingdongditch.connect_scan import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    KAREN_MODE_CONCURRENCY,
)
from dingdongditch.nmap_parser import Service, parse_nmap_xml
from dingdongditch.nmap_scanner import PROFILES, NmapNotFoundError
from dingdongditch.targets import split_targets

app = typer.Typer(
    help="Scan a host and score the risk of its open ports.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"DingDongDitch {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """DingDongDitch: ML-powered risk scoring for open ports."""


def _report(services: list[Service], as_json: bool) -> None:
    if as_json:
        print(json.dumps([s.to_dict() for s in services], indent=2))
        return

    if not services:
        console.print("No open ports found.")
        return

    table = Table(title="Open services")
    for col in ("Host", "Port", "Service", "Product / version", "Risk"):
        table.add_column(col)
    for s in services:
        risk = "[dim]model not trained yet[/dim]"
        table.add_row(s.host, f"{s.port}/{s.protocol}", s.name, s.label, risk)
    console.print(table)


class Engine(str, Enum):
    own = "own"
    nmap = "nmap"


def _scan_own(
    targets: list[str], profile: str, ports: str | None, karen_mode: bool,
    timeout: float, concurrency: int | None,
) -> list[Service]:
    hosts, port_list = own_scanner.resolve(targets, profile, ports, karen_mode)
    if concurrency is None:
        concurrency = KAREN_MODE_CONCURRENCY if karen_mode else DEFAULT_CONCURRENCY
    total = len(hosts) * len(port_list)
    err.print(
        f"[dim]Scanning {len(hosts):,} host(s) x {len(port_list):,} port(s) "
        f"with the built-in scanner ({concurrency} at once)...[/dim]"
    )
    slowest = concurrency

    with Progress(
        TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(),
        TimeRemainingColumn(), console=err, transient=True,
    ) as progress:
        task = progress.add_task("Checking ports", total=total)

        def on_slowdown(n: int) -> None:
            nonlocal slowest
            slowest = min(slowest, n)

        def on_identify(n_open: int) -> None:
            progress.update(task, description=f"Asking {n_open} open port(s) what they are",
                            total=None)

        services = own_scanner.run_scan(
            hosts, port_list, timeout=timeout, concurrency=concurrency,
            on_result=lambda: progress.advance(task),
            on_slowdown=on_slowdown, on_identify=on_identify,
        )
    if slowest < concurrency:
        err.print(
            f"[yellow]The system ran out of sockets, so the scan slowed down to about "
            f"{slowest} connections at once. Use -c {slowest} next time.[/yellow]"
        )
    return services


def _scan_nmap(
    targets: list[str], profile: str, ports: str | None, karen_mode: bool, save: Path | None
) -> list[Service]:
    tokens = split_targets(targets)
    err.print(
        f"[dim]Scanning {' '.join(tokens)} with nmap. "
        "Version detection can take a few minutes...[/dim]"
    )
    with err.status("Running nmap -sV ..."):
        return nmap_scanner.run_scan(
            tokens, profile=profile, ports=ports, save_xml=save, karen_mode=karen_mode
        )


@app.command()
def scan(
    targets: list[str] = typer.Argument(
        ..., help="One or more IPs, hostnames or subnets, e.g. 172.17.0.2 "
        "or 10.0.0.1,10.0.0.2 or 172.17.0.0/24.",
    ),
    engine: Engine = typer.Option(
        Engine.own, "--engine", "-e", help="Scanner to use: own (built in) or nmap."
    ),
    profile: str = typer.Option(
        "default", "--profile", "-P",
        help=f"Scan depth: {', '.join(PROFILES)} (quick = ~100 common ports, "
        "default = ~1,100, full = all 65,535).",
    ),
    ports: str = typer.Option(
        None, "--ports", "-p", help="Custom ports, e.g. '22,80,443' or '8000-9000'."
    ),
    karen_mode: bool = typer.Option(
        False, "--karen-mode",
        help="Demand to speak to every port's manager: all 65,535 ports unless -p is "
        f"given, {KAREN_MODE_CONCURRENCY} connections at once.",
    ),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT, "--timeout", "-t", min=0.05,
        help="Built-in scanner: seconds to wait for each port.",
    ),
    concurrency: int = typer.Option(
        None, "--concurrency", "-c", min=1, show_default=False,
        help=f"Built-in scanner: connections at once [default: {DEFAULT_CONCURRENCY}, "
        f"{KAREN_MODE_CONCURRENCY} with --karen-mode]. Lowered automatically if the system "
        "runs out of sockets.",
    ),
    save: Path = typer.Option(
        None, "--save", "-o",
        help="Also save the raw results here: JSON (own engine) or nmap XML (nmap engine).",
    ),
    as_json: bool = typer.Option(False, "--json", help="Output JSON instead of a table."),
) -> None:
    """Scan one or more targets, then analyze the results."""
    err.print("[yellow]Only scan systems you own or have written permission to test.[/yellow]")
    try:
        if engine is Engine.nmap:
            services = _scan_nmap(targets, profile, ports, karen_mode, save)
        else:
            services = _scan_own(targets, profile, ports, karen_mode, timeout, concurrency)
            if save:
                save.write_text(json.dumps([s.to_dict() for s in services], indent=2))
    except NmapNotFoundError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    except OSError as exc:
        hint = " Try a lower --concurrency." if exc.errno in (errno.EMFILE, errno.ENFILE) else ""
        err.print(f"[red]Scan failed:[/red] {exc}.{hint}")
        raise typer.Exit(1) from exc
    except (ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        err.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    _report(services, as_json)


@app.command()
def analyze(
    report: str = typer.Argument(
        ..., help="Existing nmap XML report (from `nmap -sV -oX`), or '-' for stdin."
    ),
    as_json: bool = typer.Option(False, "--json", help="Output JSON instead of a table."),
) -> None:
    """Analyze an nmap XML report you already have."""
    if report == "-":
        source = sys.stdin
    else:
        path = Path(report)
        if not path.exists():
            err.print(f"[red]File not found:[/red] {report}")
            raise typer.Exit(1)
        source = path

    try:
        services = parse_nmap_xml(source)
    except ValueError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    _report(services, as_json)


@app.command("update-db")
def update_db() -> None:
    """Download / refresh CVE data (NVD, CISA KEV, Exploit-DB)."""
    err.print("[yellow]Not implemented yet. Coming in Phase 1 (data collection).[/yellow]")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
