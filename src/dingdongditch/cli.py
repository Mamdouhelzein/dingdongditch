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
from dingdongditch.evaluate import EPSS, EvaluationError, Judged
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
POSSIBLE = "Possible only: NVD's record doesn't say which release the bug began in"


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
        sure = [s for s in scored if not s.open_ended]
        if sure:
            count = f"{len(sure)} CVE" + ("s" if len(sure) > 1 else "")
            lines += [_level(worst(sure)), f"[dim]{count}[/dim]"]
        if len(sure) < len(scored):
            # A possible match never sets the port's level, but the worst one is named.
            # On its own line, so the column stays as narrow as "KNOWN EXPLOITED".
            lines += [
                f"[dim]{'+' if sure else ''}{len(scored) - len(sure)} possible:[/dim]",
                f"[dim]{worst(scored, possible=True)}[/dim]",
            ]
    elif targets(svc):
        lines.append("[dim]no known CVEs[/dim]")
    else:
        lines.append("[dim]version unknown[/dim]")
    return "\n".join(lines)


def _indented(spaces: int, markup: str) -> None:
    """Print a line that wraps under its own indent, not back at the left edge."""
    console.print(Padding(markup, (0, 0, 0, spaces), expand=False))


def _count(scored: list[ScoredCVE], word: str) -> str:
    """'12 known CVEs (8 KNOWN EXPLOITED, 4 LOW)'"""
    counts = Counter(s.level for s in scored)
    split = ", ".join(f"{counts[level]} {level}" for level in LEVELS if counts[level])
    return f"{len(scored)} {word} CVE{'s' if len(scored) > 1 else ''} ({split})"


def _print_cves(svc: Service, scored: list[ScoredCVE]) -> None:
    sure = [s for s in scored if not s.open_ended]
    possible = [s for s in scored if s.open_ended]
    where = f"{escape(svc.host)}:{svc.port} {escape(svc.label)}"
    if sure:
        also = f", and {_count(possible, 'possible')}" if possible else ""
        console.print(f"{_level(worst(sure))} {where}: {_count(sure, 'known')}{also}")
        _print_each(sure[:SHOWN])
        if len(sure) > SHOWN:
            console.print(f"  [dim]...and {len(sure) - SHOWN} more: --json lists them all.[/dim]")
    else:
        console.print(f"{where}: no CVE names this version, {_count(possible, 'possible')}")
    if possible:
        # With sure CVEs to read first, one possible CVE is enough: the worst.
        shown = 1 if sure else SHOWN
        _indented(2, f"[dim]{escape(POSSIBLE)}:[/dim]")
        _print_each(possible[:shown])
        if len(possible) > shown:
            console.print(
                f"  [dim]...and {len(possible) - shown} more possible: "
                "--json lists them all.[/dim]"
            )


def _print_each(scored: list[ScoredCVE]) -> None:
    for s in scored:
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


def _report(services: list[Service], as_json: bool, db_path: Path | None = None) -> None:
    risks = _risks(services, db_path)
    if as_json:
        data = [s.to_dict() for s in services]
        for item, scored in zip(data, risks or [None] * len(data), strict=True):
            item["risk"] = None if scored is None else {
                "level": worst(scored),
                "possible_level": worst(scored, possible=True),
                "cves": [asdict(s) for s in scored],
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


_TOPS = ("top 1%", "top 5%", "top 10%")
_HEADINGS = ("Top 1%", "Top 5%", "Top 10%")


def _settings_words(settings: dict) -> str:
    options = ", ".join(f"{key}={value}" for key, value in settings.items() if key != "kind")
    return f"{_MODEL_NAMES[settings['kind']]} ({options})"


def _print_judged(judged: Judged, pooled: bool = False, note: str = "") -> None:
    """One table of rankings with 95% intervals, then our model against EPSS.

    Each interval goes under its number, so the table still fits 80 columns.
    """
    table = Table(show_lines=True)
    headings = ("Ranking", *_HEADINGS) if pooled else ("Ranking", *_HEADINGS, "Average precision")
    for heading in headings:
        table.add_column(heading, justify="left" if heading == "Ranking" else "right")
    for name, measures in judged.rows:
        ranges = judged.intervals[name]
        cells = [
            f"{measures[key]:.1%}\n({ranges[key][0] * 100:.0f} to {ranges[key][1] * 100:.0f})"
            for key in _TOPS
        ]
        if not pooled:
            low, high = ranges["average precision"]
            # Four decimals, as CVSS's is under 0.001, and no leading 0 so the row fits.
            ends = " to ".join(f"{end:.4f}".removeprefix("0") for end in (low, high))
            cells.append(f"{measures['average precision']:.4f}\n({ends})")
        # EPSS as it was on the test day: today's EPSS already knows what happened next.
        table.add_row("EPSS that day" if name == EPSS else name, *cells)
    console.print(table)
    if note:
        console.print(note)
    if not judged.against_epss:
        return
    gaps = [judged.against_epss[key] for key in _TOPS]
    table = Table(title="Our model against EPSS, on the same listed CVEs", title_justify="left")
    for heading in ("", *_HEADINGS):
        table.add_column(heading, justify="right" if heading else "left")
    table.add_row(
        "Ours minus EPSS, in points",
        *(f"{g.difference * 100:+.1f}\n({g.low * 100:+.0f} to {g.high * 100:+.0f})" for g in gaps),
    )
    table.add_row(
        "Only ours caught / only EPSS", *(f"{g.only_first} / {g.only_second}" for g in gaps)
    )
    table.add_row(
        "Sign test p-value",
        *("under 0.001" if g.p_value < 0.001 else f"{g.p_value:.3f}" for g in gaps),
    )
    console.print(table)
    ahead = [h for h, g in zip(_HEADINGS, gaps, strict=True) if g.beyond_chance]
    behind = [
        h for h, g in zip(_HEADINGS, gaps, strict=True) if g.high < 0 and g.p_value < 0.05
    ]
    console.print(
        "Ahead of EPSS beyond chance (interval above 0 and p under 0.05): "
        f"{', '.join(ahead).lower() or 'nowhere'}."
        + (f" Behind it: {', '.join(behind).lower()}." if behind else "")
    )


def _print_test(result: train.TestResult) -> None:
    day = result.cutoff.isoformat()
    all_of_it = result.everything
    how = "chosen on the year before" if result.tuned else "the built-in settings"
    console.print(
        f"Standing on {day}: {all_of_it.judged:,} CVEs were public and not "
        f"yet on CISA's list. CISA listed {all_of_it.listed} of them in the following year.\n"
        f"Model: {_settings_words(result.settings)}, {how}.\n"
        "How many of those would you have caught by fixing the top of each ranking "
        "(95% interval in brackets):"
    )
    _print_judged(
        all_of_it,
        note="Random guessing catches about 1%, 5% and 10%, with an average precision of "
        f"{all_of_it.listed / all_of_it.judged:.4f}.",
    )
    strict = result.without_those
    if result.said_exploited and strict:
        console.print(
            f"\nGiveaway check: {result.said_exploited} of the {all_of_it.listed} listed CVEs "
            "have a description that says they were exploited, which may have been written "
            f"after the attack. Without any CVE that says so ({strict.listed} listed left):"
        )
        _print_judged(strict)
    elif result.said_exploited:
        console.print(
            f"\nGiveaway check: all {result.said_exploited} listed CVEs have a description "
            "that says they were exploited, so nothing is left to judge without them."
        )
    else:
        console.print(
            "\nGiveaway check: no listed CVE's description says it was exploited."
        )
    if result.epss_missing:
        err.print(
            f"[yellow]No EPSS scores saved for {day}, so EPSS isn't compared. Run "
            f"`dingdongditch update-db --epss-date {day}` to add them.[/yellow]"
        )


def _print_pooled(results: list[train.TestResult]) -> None:
    both = train.pooled(results)
    if both is None:
        err.print(
            "[yellow]The test years overlap, so they aren't added up: a CVE would count "
            "twice. Use days at least a year apart.[/yellow]"
        )
        return
    everything, strict = both
    console.print(
        f"\nAll {len(results)} test days together: {everything.listed} listed CVEs, each "
        "judged in its own year."
    )
    _print_judged(everything, pooled=True)
    if EPSS not in everything.caught:
        err.print("[yellow]EPSS is left out: not every test day has its scores saved.[/yellow]")
    if strict and strict.listed < everything.listed:
        console.print(
            f"\nThe same without any CVE whose description says it was exploited "
            f"({strict.listed} listed left):"
        )
        _print_judged(strict, pooled=True)


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
    test_dates: list[str] = typer.Option(
        [], "--test", metavar="YYYY-MM-DD",
        help="Don't save a model: train on what was known that day, and compare it with "
        "CVSS and EPSS on the year after, with 95% intervals. Give it more than once, "
        "a year or more apart, to also add the test years up.",
    ),
    tune: bool = typer.Option(
        False, "--tune",
        help="With --test: choose the model's settings again for each test day, on the "
        "year before it, instead of using the built-in ones. With --xgboost, XGBoost "
        "is tried as well. Much slower.",
    ),
) -> None:
    """Train the model that ranks CVEs by how likely they are to be exploited."""
    if use_xgboost and not train.xgboost_installed():
        err.print(f"[red]{escape(str(train.MissingXGBoost()))}[/red]")
        raise typer.Exit(1)
    try:
        cutoffs = sorted({date.fromisoformat(text) for text in test_dates})
    except ValueError as exc:
        raise typer.BadParameter(
            f"{exc}. Use YYYY-MM-DD, e.g. 2025-05-01.", param_hint="--test"
        ) from exc
    if tune and not cutoffs:
        raise typer.BadParameter("--tune only works with --test.", param_hint="--tune")
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
        if cutoffs:
            grid = train.LOGISTIC + (train.XGBOOST if use_xgboost else []) if tune else None
            results = []
            for cutoff in cutoffs:
                doing = "Choosing settings, then training" if tune else "Training"
                with err.status(f"{doing} on what was known on {cutoff.isoformat()}..."):
                    result = train.time_travel_test(con, cutoff, settings, date.today(), grid)
                if results:
                    console.print()
                _print_test(result)
                if tune and not result.tuned:
                    err.print(
                        "[yellow]CISA's list was too young a year before "
                        f"{cutoff.isoformat()} to choose settings on, so the built-in ones "
                        "were used.[/yellow]"
                    )
                results.append(result)
            if len(results) > 1:
                _print_pooled(results)
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
