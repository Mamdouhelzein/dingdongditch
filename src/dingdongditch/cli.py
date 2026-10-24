"""dingdongditch command-line interface."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from dingdongditch import __version__
from dingdongditch.nmap_parser import Service, parse_nmap_xml
from dingdongditch.nmap_scanner import PROFILES, NmapNotFoundError, run_scan

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


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="IP, hostname or CIDR range to scan (e.g. 192.168.56.101)."
    ),
    profile: str = typer.Option(
        "default", "--profile", "-P",
        help=f"Scan depth: {', '.join(PROFILES)} (quick = top 100 ports, full = all ports).",
    ),
    ports: str = typer.Option(
        None, "--ports", "-p", help="Custom ports, e.g. '22,80,443' or '1-1024'."
    ),
    save: Path = typer.Option(None, "--save", "-o", help="Also save the raw nmap XML here."),
    as_json: bool = typer.Option(False, "--json", help="Output JSON instead of a table."),
) -> None:
    """Scan a target with nmap, then analyze the results."""
    err.print(
        "[yellow]Only scan systems you own or have written permission to test.[/yellow]\n"
        f"[dim]Scanning {target} (profile: {ports and 'custom ports' or profile}). "
        "Version detection can take a few minutes...[/dim]"
    )
    try:
        with err.status("Running nmap -sV ..."):
            services = run_scan(target, profile=profile, ports=ports, save_xml=save)
    except NmapNotFoundError as exc:
        err.print(f"[red]{exc}[/red]")
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
