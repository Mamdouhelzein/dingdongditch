"""portrisk command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from portrisk import __version__
from portrisk.nmap_parser import parse_nmap_xml

app = typer.Typer(
    help="Score the risk of open ports from an nmap -sV scan.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"portrisk {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """portrisk: ML-powered risk scoring for open ports."""


@app.command()
def scan(
    report: str = typer.Argument(
        ..., help="nmap XML report (from `nmap -sV -oX`), or '-' for stdin."
    ),
    as_json: bool = typer.Option(False, "--json", help="Output JSON instead of a table."),
) -> None:
    """Analyze an nmap XML report."""
    if report == "-":
        source = sys.stdin
    else:
        path = Path(report)
        if not path.exists():
            console.print(f"[red]File not found:[/red] {report}")
            raise typer.Exit(1)
        source = path

    try:
        services = parse_nmap_xml(source)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if as_json:
        print(json.dumps([s.to_dict() for s in services], indent=2))
        return

    if not services:
        console.print("No open ports found in the report.")
        return

    table = Table(title="Open services")
    for col in ("Host", "Port", "Service", "Product / version", "Risk"):
        table.add_column(col)
    for s in services:
        risk = "[dim]model not trained yet[/dim]"
        table.add_row(s.host, f"{s.port}/{s.protocol}", s.name, s.label, risk)
    console.print(table)


@app.command("update-db")
def update_db() -> None:
    """Download / refresh CVE data (NVD, CISA KEV, Exploit-DB)."""
    console.print("[yellow]Not implemented yet. Coming in Phase 1 (data collection).[/yellow]")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
