"""dingdongditch command-line interface."""

from __future__ import annotations

import errno
import json
import sqlite3
import subprocess
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from dingdongditch import __version__, collect, db, nmap_scanner, nvd, own_scanner
from dingdongditch.connect_scan import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    Recheck,
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
        if s.findings:
            risk = f"[bold red]{escape(s.findings[0].status)}[/bold red]"
        # Everything below comes from the scanned service: escape it so text like
        # "[red]" in a banner or page title can't restyle or fake the output.
        product = escape(s.label)
        if s.http_title:
            product += f"\n[dim]{escape(s.http_title)}[/dim]"
        if s.tls_cert:
            cert = s.tls_cert
            product += f"\n[dim]cert: {escape(cert['subject'] or '?')}, "
            product += f"until {escape(cert['not_after'])}[/dim]"
            if cert["problems"]:
                product += f"\n[yellow]{escape(', '.join(cert['problems']))}[/yellow]"
        table.add_row(s.host, f"{s.port}/{s.protocol}", escape(s.name), product, risk)
    console.print(table)

    seen: set[str] = set()
    for s in services:
        if s.os_guess and s.host not in seen:
            seen.add(s.host)
            console.print(f"OS guess for {escape(s.host)}: [bold]{escape(s.os_guess)}[/bold]")
            console.print(f"[dim]  from {escape('; '.join(s.os_evidence))}[/dim]")

    for s in services:
        for finding in s.findings:
            console.print(
                f"[bold red]{escape(finding.status)}[/bold red] "
                f"{escape(s.host)}:{s.port} {escape(finding.title)}"
            )
            console.print(f"  Why: {escape(finding.why)}")
            console.print(f"  Fix: {escape(finding.fix)}")


class Engine(str, Enum):
    own = "own"
    nmap = "nmap"


def _scan_own(
    targets: list[str], profile: str, ports: str | None, karen_mode: bool,
    timeout: float, concurrency: int,
) -> list[Service]:
    hosts, port_list = own_scanner.resolve(targets, profile, ports, karen_mode)
    total = len(hosts) * len(port_list)
    err.print(
        f"[dim]Scanning {len(hosts):,} host(s) x {len(port_list):,} port(s) "
        f"with the built-in scanner ({concurrency} at once)...[/dim]"
    )
    slowest = concurrency
    recheck: Recheck | None = None

    with Progress(
        TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(),
        TimeRemainingColumn(), console=err, transient=True,
    ) as progress:
        task = progress.add_task("Checking ports", total=total)

        def on_slowdown(n: int) -> None:
            nonlocal slowest
            slowest = min(slowest, n)

        def on_recheck(update: Recheck) -> None:
            nonlocal recheck
            recheck = update
            if update.status == "started":
                progress.update(
                    task, description=f"Rechecking {update.timed_out:,} port(s) that timed out",
                    total=None,
                )

        def on_identify(n_open: int) -> None:
            progress.update(task, description=f"Asking {n_open} open port(s) what they are",
                            total=None)

        services = own_scanner.run_scan(
            hosts, port_list, timeout=timeout, concurrency=concurrency,
            on_result=lambda: progress.advance(task),
            on_slowdown=on_slowdown, on_identify=on_identify, karen_mode=karen_mode,
            on_recheck=on_recheck,
        )
    if recheck and recheck.status == "done":
        err.print(
            f"[dim]Rechecked {recheck.timed_out:,} port(s) that timed out: "
            f"{recheck.opened:,} turned out to be open.[/dim]"
        )
    elif recheck and recheck.status == "skipped":
        err.print(
            f"[yellow]{recheck.timed_out:,} ports timed out, too many to recheck. That's normal "
            "behind a firewall, but with no firewall, open ports may be missing: "
            "try -c 100 -t 3.[/yellow]"
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
        "given, plus every extra and safe check.",
    ),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT, "--timeout", "-t", min=0.05,
        help="Built-in scanner: seconds to wait for each port.",
    ),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY, "--concurrency", "-c", min=1,
        help="Built-in scanner: connections at once. Lowered automatically if the system "
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
def update_db(
    db_path: Path = typer.Option(
        None, "--db",
        help=f"Database file. Default: ${db.ENV_VAR} if set, else a per-user data folder.",
    ),
    full: bool = typer.Option(
        False, "--full",
        help="Check every year of NVD data, not just the last week's changes.",
    ),
) -> None:
    """Download or refresh the vulnerability data (NVD, CISA KEV, Exploit-DB, EPSS)."""
    path = db_path or db.default_path()
    try:
        con = db.connect(path)
    except (db.DatabaseError, OSError) as exc:
        err.print(f"[red]Can't open the database:[/red] {exc}")
        raise typer.Exit(1) from exc

    def nvd_progress(name: str, count: int | None) -> None:
        news = "unchanged" if count is None else f"{count:,} CVEs"
        err.print(f"  NVD {name}: {news}", style="dim")

    session = collect.new_session()
    steps = [
        ("CISA KEV", "exploited CVEs", lambda: collect.update_kev(con, session)),
        ("EPSS", "scored CVEs", lambda: collect.update_epss(con, session)),
        ("Exploit-DB", "CVEs with a public exploit",
         lambda: collect.update_exploitdb(con, session)),
        ("NVD", "CVEs added or changed",
         lambda: nvd.update_nvd(con, session, full=full, report=nvd_progress)),
    ]
    failed = False
    try:
        for name, what, step in steps:
            try:
                with err.status(f"Downloading {name}..."):
                    count = step()
            except (collect.DownloadError, sqlite3.Error) as exc:
                err.print(f"[red]{name} failed:[/red] {exc}")
                failed = True
            else:
                console.print(f"{name}: {count:,} {what}")
        totals = [
            (label, con.execute(f"SELECT COUNT(DISTINCT {column}) FROM {table}").fetchone()[0])
            for label, table, column in (
                ("CVEs", "cve", "id"),
                ("Products", "cve_cpe", "vendor || ':' || product"),
                ("Exploited (KEV)", "kev", "cve_id"),
                ("With a public exploit", "exploitdb", "cve_id"),
                ("With an EPSS score", "epss", "cve_id"),
            )
        ]
    finally:
        con.close()
    console.print(f"\nDatabase: {escape(str(path))}", soft_wrap=True)
    for label, count in totals:
        console.print(f"  {label}: {count:,}")
    if failed:
        err.print(
            "[yellow]Some sources failed. Their old data was kept; run it again later.[/yellow]"
        )
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
