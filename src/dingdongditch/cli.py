"""dingdongditch command-line interface."""

from __future__ import annotations

import errno
import json
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict
from datetime import date, timedelta
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from dingdongditch import (
    __version__,
    collect,
    db,
    features,
    nmap_scanner,
    nvd,
    own_scanner,
    train,
)
from dingdongditch.connect_scan import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    Recheck,
)
from dingdongditch.evaluate import EvaluationError
from dingdongditch.matcher import targets
from dingdongditch.nmap_parser import Service, parse_nmap_xml
from dingdongditch.nmap_scanner import PROFILES, NmapNotFoundError
from dingdongditch.scorer import LEVELS, ModelError, ScoredCVE, Scorer, worst
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


_LEVEL_STYLES = {"KNOWN EXPLOITED": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": ""}
SHOWN = 3  # CVEs listed under the table for each port; --json has them all


def _risks(services: list[Service], db_path: Path | None) -> list[list[ScoredCVE]] | None:
    """Each service's scored CVEs, or None when there's no database or model yet."""
    if not any(targets(s) for s in services):  # nothing has a version to look up
        return [[] for _ in services]
    path = db_path or db.default_path()
    try:
        scorer = Scorer.open(path, path.with_name(train.MODEL_FILE))
    except ModelError as exc:
        err.print(f"[yellow]No risk scores: {escape(str(exc))}[/yellow]", soft_wrap=True)
        return None
    try:
        with err.status("Looking up known CVEs..."):
            return scorer.score_services(services)
    except sqlite3.Error as exc:
        err.print(f"[yellow]No risk scores: the database failed: {escape(str(exc))}[/yellow]")
        return None
    finally:
        scorer.close()


def _level(level: str) -> str:
    style = _LEVEL_STYLES[level]
    return f"[{style}]{level}[/{style}]" if style else level


def _risk_cell(svc: Service, scored: list[ScoredCVE] | None) -> str:
    lines = [f"[bold red]{escape(svc.findings[0].status)}[/bold red]"] if svc.findings else []
    if scored is None:
        lines.append("[dim]no risk data[/dim]")
    elif scored:
        count = f"{len(scored)} CVE" + ("s" if len(scored) > 1 else "")
        lines += [_level(worst(scored)), f"[dim]{count}[/dim]"]
    elif targets(svc):
        lines.append("[dim]no known CVEs[/dim]")
    else:
        lines.append("[dim]version unknown[/dim]")
    return "\n".join(lines)


def _indented(spaces: int, markup: str) -> None:
    """Print a line that wraps under its own indent, not back at the left edge."""
    console.print(Padding(markup, (0, 0, 0, spaces), expand=False))


def _print_cves(svc: Service, scored: list[ScoredCVE]) -> None:
    counts = Counter(s.level for s in scored)
    split = ", ".join(f"{counts[level]} {level}" for level in LEVELS if counts[level])
    console.print(
        f"{_level(worst(scored))} {escape(svc.host)}:{svc.port} {escape(svc.label)}: "
        f"{len(scored)} known CVE{'s' if len(scored) > 1 else ''} ({split})"
    )
    for s in scored[:SHOWN]:
        facts = [f"riskier than {s.riskier_than:.1%} of CVEs"]
        if s.cvss is not None:
            facts.append(f"CVSS {s.cvss:.1f}")
        if s.epss is not None:
            facts.append(f"EPSS {s.epss:.1%}")
        maybe = "" if s.certain else ", only some of the versions it could be"
        _indented(2, f"{s.cve_id} {_level(s.level)} ({', '.join(facts)}{escape(maybe)})")
        _indented(4, f"[dim]{escape(s.summary)}[/dim]")
        why = s.reasons
        if s.rule:  # the rule already says what Exploit-DB has
            why = [s.rule, *(r for r in why if not r.endswith("on Exploit-DB"))]
        if s.level == "KNOWN EXPLOITED":
            why = ["on CISA's list of CVEs used in real attacks", *why]
        _indented(4, f"Why: {escape('; '.join(why) or 'no single clue stands out')}")
        if s.fixed_in:
            fix = f"upgrade to {s.fixed_in} or later"
        elif s.last_affected:
            fix = f"upgrade to a release newer than {s.last_affected}"
        else:
            fix = "NVD lists no fixed release: check the vendor's advisories"
        _indented(4, f"Fix: {escape(fix)}")
    if len(scored) > SHOWN:
        console.print(f"  [dim]...and {len(scored) - SHOWN} more: --json lists them all.[/dim]")


def _report(services: list[Service], as_json: bool, db_path: Path | None = None) -> None:
    risks = _risks(services, db_path)
    if as_json:
        data = [s.to_dict() for s in services]
        for item, scored in zip(data, risks or [None] * len(data), strict=True):
            item["risk"] = None if scored is None else {
                "level": worst(scored), "cves": [asdict(s) for s in scored],
            }
        print(json.dumps(data, indent=2))
        return

    if not services:
        console.print("No open ports found.")
        return

    scored_list = risks or [None] * len(services)
    table = Table(title="Open services")
    for col in ("Host", "Port", "Service", "Product / version", "Risk"):
        table.add_column(col)
    for s, scored in zip(services, scored_list, strict=True):
        risk = _risk_cell(s, scored)
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

    for s, scored in zip(services, scored_list, strict=True):
        if scored:
            _print_cves(s, scored)
    if any(scored_list):
        console.print(
            "[dim]CVEs are matched on the version number alone. Linux distributions often "
            "patch a bug without changing it, so check the installed package too.[/dim]"
        )


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
    db_path: Path = typer.Option(
        None, "--db",
        help=f"Vulnerability database. Default: ${db.ENV_VAR} if set, else a per-user data "
        "folder. The model is read from next to it.",
    ),
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

    _report(services, as_json, db_path)


@app.command()
def analyze(
    report: str = typer.Argument(
        ..., help="Existing nmap XML report (from `nmap -sV -oX`), or '-' for stdin."
    ),
    as_json: bool = typer.Option(False, "--json", help="Output JSON instead of a table."),
    db_path: Path = typer.Option(
        None, "--db",
        help=f"Vulnerability database. Default: ${db.ENV_VAR} if set, else a per-user data "
        "folder. The model is read from next to it.",
    ),
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

    _report(services, as_json, db_path)


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
    epss_dates: list[str] = typer.Option(
        [], "--epss-date", metavar="YYYY-MM-DD",
        help="Also save the EPSS scores from this past day. Can be given more than once.",
    ),
    no_train: bool = typer.Option(
        False, "--no-train",
        help="Don't retrain the risk model afterwards (it takes about 2 minutes).",
    ),
) -> None:
    """Download or refresh the vulnerability data, then retrain the risk model."""
    try:
        days = [date.fromisoformat(text) for text in epss_dates]
    except ValueError as exc:
        raise typer.BadParameter(
            f"{exc}. Use YYYY-MM-DD, e.g. 2025-05-01.", param_hint="--epss-date"
        ) from exc
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
        *[
            (f"EPSS on {day}", "scored CVEs",
             lambda day=day: collect.update_epss_history(con, session, day))
            for day in days
        ],
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
        if not no_train and totals[0][1]:
            failed |= not _train_after_update(con, path.with_name(train.MODEL_FILE))
        elif not no_train:
            err.print("[yellow]No CVEs yet, so no risk model was trained.[/yellow]")
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


def _train_after_update(con: sqlite3.Connection, out: Path) -> bool:
    """Retrain the default model on the fresh data. Returns whether it worked."""
    started = time.monotonic()
    try:
        with err.status("Training the risk model, about 2 minutes..."):
            cves, exploited = _train_and_save(con, train.DEFAULT, out)
    except (EvaluationError, ValueError, sqlite3.Error) as exc:
        err.print(f"[red]Training failed:[/red] {escape(str(exc))}")
        return False
    _print_trained(train.DEFAULT, cves, exploited, started, out)
    return True


_MODEL_NAMES = {"logistic": "a logistic regression", "xgboost": "an XGBoost"}


def _train_and_save(con: sqlite3.Connection, settings: dict, out: Path) -> tuple[int, int]:
    """Train on everything known today and save the model. Returns (CVEs, exploited)."""
    # Everything known today: CVEs published up to now, every KEV entry so far.
    today = date.today() + timedelta(days=1)
    frame = features.load(con, today)
    model = train.fit(frame, today, settings)
    exploited = int(features.kev_between(frame, None, today).sum())
    train.save(
        model, out,
        {"settings": settings, "trained": collect.utc_now(), "cves": len(frame),
         "exploited": exploited, "version": __version__,
         "spread": train.score_spread(model, frame)},
    )
    return len(frame), exploited


def _print_trained(settings: dict, cves: int, exploited: int, started: float, out: Path) -> None:
    minutes = (time.monotonic() - started) / 60
    console.print(
        f"Trained {_MODEL_NAMES[settings['kind']]} model on {cves:,} CVEs, "
        f"{exploited:,} of them exploited, in {minutes:.0f} min."
    )
    console.print(f"Saved to {escape(str(out))}", soft_wrap=True)


def _print_test(result: train.TestResult) -> None:
    console.print(
        f"Standing on {result.cutoff.isoformat()}: {result.judged:,} CVEs were public and not "
        f"yet on CISA's list. CISA listed {result.listed} of them in the following year.\n"
        "How many of those would you have caught by fixing the top of each ranking:"
    )
    table = Table()
    for heading in ("Ranking", "Top 1%", "Top 5%", "Top 10%", "Average precision"):
        table.add_column(heading, justify="left" if heading == "Ranking" else "right")
    for name, measures in result.rows:
        table.add_row(
            name,
            *(f"{measures[key]:.1%}" for key in ("top 1%", "top 5%", "top 10%")),
            f"{measures['average precision']:.4f}",
        )
    console.print(table)
    console.print(
        f"Random guessing catches about 1%, 5% and 10%, with an average precision of "
        f"{result.listed / result.judged:.4f}."
    )
    if result.epss_missing:
        day = result.cutoff.isoformat()
        err.print(
            f"[yellow]No EPSS scores saved for {day}, so EPSS isn't compared. Run "
            f"`dingdongditch update-db --epss-date {day}` to add them.[/yellow]"
        )


@app.command("train")
def train_command(
    db_path: Path = typer.Option(
        None, "--db",
        help=f"Database file. Default: ${db.ENV_VAR} if set, else a per-user data folder.",
    ),
    model_path: Path = typer.Option(
        None, "--model", help=f"Where to save the model. Default: {train.MODEL_FILE} next to "
        "the database.",
    ),
    use_xgboost: bool = typer.Option(
        False, "--xgboost",
        help="Use XGBoost instead of logistic regression: about 15 minutes instead of 2, "
        "and about as good.",
    ),
    test_date: str = typer.Option(
        None, "--test", metavar="YYYY-MM-DD",
        help="Don't save a model: train on what was known that day, and compare it with "
        "CVSS and EPSS on the year after.",
    ),
) -> None:
    """Train the model that ranks CVEs by how likely they are to be exploited."""
    if use_xgboost and not train.xgboost_installed():
        err.print(f"[red]{escape(str(train.MissingXGBoost()))}[/red]")
        raise typer.Exit(1)
    try:
        cutoff = date.fromisoformat(test_date) if test_date else None
    except ValueError as exc:
        raise typer.BadParameter(
            f"{exc}. Use YYYY-MM-DD, e.g. 2025-05-01.", param_hint="--test"
        ) from exc
    path = db_path or db.default_path()
    if not path.exists():
        err.print(f"[red]No database at {path}.[/red] Run `dingdongditch update-db` first.")
        raise typer.Exit(1)
    try:
        con = db.connect(path)
    except db.DatabaseError as exc:
        err.print(f"[red]Can't open the database:[/red] {exc}")
        raise typer.Exit(1) from exc

    settings = train.XGBOOST_BEST if use_xgboost else train.DEFAULT
    started = time.monotonic()
    try:
        if not con.execute("SELECT 1 FROM cve LIMIT 1").fetchone():
            err.print("[red]The database has no CVEs yet.[/red] Run `dingdongditch update-db`.")
            raise typer.Exit(1)
        if cutoff:
            with err.status(f"Training on what was known on {cutoff.isoformat()}..."):
                result = train.time_travel_test(con, cutoff, settings, date.today())
            _print_test(result)
            return
        out = model_path or path.with_name(train.MODEL_FILE)
        with err.status("Training on every CVE known today..."):
            cves, exploited = _train_and_save(con, settings, out)
    except EvaluationError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    finally:
        con.close()
    _print_trained(settings, cves, exploited, started, out)


if __name__ == "__main__":
    app()
