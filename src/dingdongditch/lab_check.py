"""Check the CVE matcher against lab services whose real CVEs are known.

A scan lists dozens of CVEs per service, and nobody can say from the list alone how
many are right. This reads a small answer key (data/lab_truth.json in the
repository) and reports, for each service in it:

  found     CVEs known to affect that release that the matcher reports as sure
  possible  ones it only reports as possible (NVD names no first affected release)
  missed    ones it doesn't report at all
  wrong     CVEs the key says can't be called sure that the matcher calls sure anyway

and how many of its sure matches the key says nothing about. Recall is found out of
all the known CVEs. Precision can't be measured until those unlabelled matches are
checked by hand, so the report says how many there are instead of guessing.

    python -m dingdongditch.lab_check data/lab_truth.json
    python -m dingdongditch.lab_check data/lab_truth.json --db ~/lab/vulns.db
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from dingdongditch import db
from dingdongditch.matcher import match_service, targets
from dingdongditch.nmap_parser import Service

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


class TruthError(Exception):
    """The answer key can't be used as it is."""


@dataclass(frozen=True)
class Entry:
    lab: str
    product: str
    cpe: str  # as the scanner writes it: cpe:/a:vendor:product:version
    affected: dict[str, str] = field(default_factory=dict)  # CVE -> how we know
    not_sure: dict[str, str] = field(default_factory=dict)  # CVE -> why it can't be sure


@dataclass(frozen=True)
class Result:
    entry: Entry
    found: list[str]
    possible: list[str]
    missed: list[str]
    wrong: list[str]
    sure_matches: int  # every sure match, labelled or not
    possible_matches: int
    unlabelled: int  # sure matches the answer key says nothing about


def load_truth(path: str | Path) -> list[Entry]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = [
            Entry(
                lab=item["lab"],
                product=item["product"],
                cpe=item["cpe"],
                affected=item.get("affected", {}),
                not_sure=item.get("not_sure", {}),
            )
            for item in data["services"]
        ]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TruthError(f"Can't read the answer key at {path}: {exc!r}") from exc
    for entry in entries:
        if not targets(_service(entry)):
            raise TruthError(f"{entry.product}: {entry.cpe!r} isn't cpe:/a:vendor:product:version")
        for cve in [*entry.affected, *entry.not_sure]:
            if not _CVE.fullmatch(cve):
                raise TruthError(f"{entry.product}: {cve!r} isn't a CVE id")
        if both := set(entry.affected) & set(entry.not_sure):
            raise TruthError(f"{entry.product}: {sorted(both)} can't be in both lists")
    return entries


def _service(entry: Entry) -> Service:
    return Service("lab", 0, "tcp", "open", product=entry.product, cpes=[entry.cpe])


def check(con: sqlite3.Connection, entries: list[Entry]) -> list[Result]:
    results = []
    for entry in entries:
        matches = match_service(con, _service(entry))
        sure = {m.cve_id for m in matches if not m.open_ended}
        possible = {m.cve_id for m in matches if m.open_ended}
        results.append(
            Result(
                entry=entry,
                found=sorted(set(entry.affected) & sure),
                possible=sorted(set(entry.affected) & possible),
                missed=sorted(set(entry.affected) - sure - possible),
                wrong=sorted(set(entry.not_sure) & sure),
                sure_matches=len(sure),
                possible_matches=len(possible),
                unlabelled=len(sure - set(entry.affected) - set(entry.not_sure)),
            )
        )
    return results


def summary(results: list[Result]) -> dict[str, int]:
    """Totals over every service: the numbers to quote."""
    keys = ("found", "possible", "missed", "wrong")
    totals = {key: sum(len(getattr(r, key)) for r in results) for key in keys}
    totals["known"] = totals["found"] + totals["possible"] + totals["missed"]
    totals["sure_matches"] = sum(r.sure_matches for r in results)
    totals["possible_matches"] = sum(r.possible_matches for r in results)
    totals["unlabelled"] = sum(r.unlabelled for r in results)
    return totals


def report(results: list[Result]) -> str:
    lines = []
    for r in results:
        lines.append(
            f"{r.entry.lab}: {r.entry.product}: {r.sure_matches} sure and "
            f"{r.possible_matches} possible matches"
        )
        for label, cves in (
            ("found", r.found), ("only possible", r.possible), ("MISSED", r.missed),
            ("WRONGLY SURE", r.wrong),
        ):
            if cves:
                lines.append(f"  {label}: {', '.join(cves)}")
    t = summary(results)
    lines.append("")
    if t["known"]:
        lines.append(
            f"Recall: {t['found']} of {t['known']} known CVEs reported as sure "
            f"({t['found'] / t['known']:.0%}), {t['possible']} only as possible, "
            f"{t['missed']} missed."
        )
    lines.append(f"Wrongly sure: {t['wrong']}.")
    lines.append(
        f"Precision isn't known yet: {t['unlabelled']} of the {t['sure_matches']} sure "
        "matches aren't in the answer key. Label them to measure it."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dingdongditch.lab_check",
        description="Check the CVE matcher against lab services whose real CVEs are known.",
    )
    parser.add_argument("truth", help="the answer key, e.g. data/lab_truth.json")
    parser.add_argument("--db", help="the vulnerability database (default: the usual one)")
    args = parser.parse_args(argv)
    path = Path(args.db) if args.db else db.default_path()
    if not path.exists():
        print(f"No vulnerability database at {path}: run `dingdongditch update-db`.")
        return 1
    try:
        entries = load_truth(args.truth)
        con = db.connect(path)
    except (TruthError, db.DatabaseError) as exc:
        print(exc)
        return 1
    try:
        results = check(con, entries)
    finally:
        con.close()
    print(report(results))
    totals = summary(results)
    return 1 if totals["missed"] or totals["wrong"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
