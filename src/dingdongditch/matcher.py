"""Find the CVEs that affect a scanned service, from NVD's lists of affected products.

NVD lists each CVE's products as CPE names, either one exact version
("cpe:2.3:a:samba:samba:3.0.20:...") or "any version" plus a range ("before
3.0.25"). The scanner gives each service a CPE in the same vendor:product naming,
so matching is a lookup plus a version comparison.

Two NVD habits need care:
  OpenSSH 4.7p1 is often listed as just 4.7, so a patch like p1, a or -P1 of a
  listed release counts as that release. 2.0rc1 does not count as 2.0.
  Some releases are split in two fields: 3.0.20 plus update "a" means 3.0.20a.

Sometimes the scanner can only narrow a version down to a few releases: PostgreSQL
says "8.3" and "one of 8.3.0-8.3.7". Then every release is checked, and a CVE that
affects only some of them is marked as not certain.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

from dingdongditch.nmap_parser import Service
from dingdongditch.versions import compare, in_range, sort_key

_CPE_SPLIT = re.compile(r"(?<!\\):")  # colons inside CPE fields are escaped as \:
_RELEASE = re.compile(r"[\d.]+")
_PATCH = re.compile(r"[-_.]?(?:p\d+|[a-z])")  # 4.7 -> 4.7p1, 5.0.51 -> 5.0.51a, 9.4.2 -> -P1
_ONE_OF = re.compile(r"^one of (.+)$")


@dataclass(frozen=True)
class Match:
    cve_id: str
    certain: bool  # False: only some of the releases the service could be are affected
    fixed_in: str | None  # the first release NVD lists as no longer affected, if it says


def _patch_of(version: str, release: str) -> bool:
    """Whether `version` is a patch of `release`, like 4.7p1 of 4.7."""
    version, release = version.lower(), release.lower()
    if not _RELEASE.fullmatch(release) or not version.startswith(release):
        return False
    return bool(_PATCH.fullmatch(version[len(release) :]))


def _affects(cpe: str, limits: tuple, version: str) -> bool:
    """Whether one of NVD's CPE match rows covers this version."""
    fields = _CPE_SPLIT.split(cpe)
    listed, update = fields[5], fields[6]
    if listed == "*":
        return in_range(version, *limits)  # no limits at all means every version
    if listed == "-":  # NVD's "no version applies"
        return False
    if update not in ("*", "-", ""):
        return compare(version, listed + update) == 0
    return compare(version, listed) == 0 or _patch_of(version, listed)


def match_versions(
    con: sqlite3.Connection, vendor: str, product: str, versions: list[str]
) -> list[Match]:
    """CVEs affecting any of `versions` of vendor:product. Rejected CVEs are left out."""
    if not versions:
        return []
    affected: dict[str, set[str]] = {}
    fixes: dict[str, list[str]] = {}
    rows = con.execute(
        """
        SELECT p.cve_id, p.cpe, p.version_start_including, p.version_start_excluding,
               p.version_end_including, p.version_end_excluding
        FROM cve_cpe p JOIN cve c ON c.id = p.cve_id
        WHERE p.vendor = ? AND p.product = ? AND c.status != 'Rejected'
        """,
        (vendor, product),
    )
    for cve_id, cpe, *limits in rows:
        hit = {version for version in versions if _affects(cpe, tuple(limits), version)}
        if not hit:
            continue
        affected.setdefault(cve_id, set()).update(hit)
        if limits[3]:  # versionEndExcluding: the first release without the bug
            fixes.setdefault(cve_id, []).append(limits[3])
    return [
        Match(
            cve_id,
            certain=len(hit) == len(set(versions)),
            fixed_in=min(fixes[cve_id], key=sort_key) if cve_id in fixes else None,
        )
        for cve_id, hit in sorted(affected.items())
    ]


def _expand(item: str) -> list[str]:
    """'8.3.0-8.3.7' -> 8.3.0, 8.3.1, ... 8.3.7. A single release stays as it is."""
    first, sep, last = item.partition("-")
    if not sep:
        return [item]
    a, b = first.split("."), last.split(".")
    if a[:-1] != b[:-1] or not (a[-1].isdigit() and b[-1].isdigit()):
        return [first, last]
    stem = ".".join(a[:-1])
    return [f"{stem}.{n}" if stem else str(n) for n in range(int(a[-1]), int(b[-1]) + 1)]


def targets(svc: Service) -> list[tuple[str, str, list[str]]]:
    """(vendor, product, possible versions) for each application CPE of a service."""
    found = []
    candidates = []
    if m := _ONE_OF.match(svc.extrainfo):
        candidates = [v for item in m[1].split(", ") for v in _expand(item.strip())]
    for cpe in svc.cpes:
        fields = cpe.split(":")
        if len(fields) < 4 or fields[1] != "/a":
            continue  # operating systems and hardware are not matched
        vendor, product = fields[2], fields[3]
        version = fields[4] if len(fields) > 4 else ""
        versions = candidates or ([version] if version else svc.version.split()[:1])
        if versions:
            found.append((vendor, product, versions))
    return found


def match_service(con: sqlite3.Connection, svc: Service) -> list[Match]:
    """Every CVE that affects this service, or [] if its product or version is unknown."""
    merged: dict[str, Match] = {}
    for vendor, product, versions in targets(svc):
        for match in match_versions(con, vendor, product, versions):
            old = merged.get(match.cve_id)
            if old:
                fixes = [f for f in (old.fixed_in, match.fixed_in) if f]
                match = Match(
                    match.cve_id,
                    old.certain or match.certain,
                    min(fixes, key=sort_key) if fixes else None,
                )
            merged[match.cve_id] = match
    return sorted(merged.values(), key=lambda m: m.cve_id)
