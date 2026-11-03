"""Rebuild src/dingdongditch/data/postgres_lines.json from PostgreSQL's source.

PostgreSQL's answer to our probe (protocol 4.0) is an error that names the
source file and line it came from. This finds that line in every release:

    python scripts/make_postgres_lines.py CACHE_DIR

CACHE_DIR keeps the downloaded source files (about 80 MB) so a rerun only
fetches new releases. Delete it when you're done.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = "https://github.com/postgres/postgres"
RAW = "https://raw.githubusercontent.com/postgres/postgres/{tag}/{path}"
# Where ProcessStartupPacket lives: postmaster.c until 17, then backend_startup.c.
PATHS = ["src/backend/postmaster/postmaster.c", "src/backend/tcop/backend_startup.c"]
OUT = Path(__file__).parent.parent / "src" / "dingdongditch" / "data" / "postgres_lines.json"


def release_tags() -> list[str]:
    """Release tags from 7.4 (the first with protocol 3.0): REL7_4, REL8_3_1, REL_17_2."""
    refs = subprocess.run(["git", "ls-remote", "--tags", REPO], capture_output=True,
                          text=True, check=True).stdout
    tags = set(re.findall(r"refs/tags/(REL_?\d+_\d+(?:_\d+)?)$", refs, re.MULTILINE))
    return sorted((t for t in tags if version_key(t) >= (7, 4)), key=version_key)


def version_key(tag: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", tag))


def version_name(tag: str) -> str:
    """REL7_4 -> 7.4.0, REL8_3_1 -> 8.3.1, REL_17_2 -> 17.2."""
    parts = list(version_key(tag))
    if parts[0] < 10 and len(parts) == 2:
        parts.append(0)
    return ".".join(map(str, parts))


def error_lines(source: str) -> list[int]:
    """Lines the compiler may report for the 'unsupported frontend protocol' ereport.

    A multi-line macro call can be reported at its first or last line, so keep
    from the `ereport(` line to its closing parenthesis.
    """
    lines = source.splitlines()
    msg = next(i for i, line in enumerate(lines) if "unsupported frontend protocol" in line)
    start = max(i for i in range(msg + 1) if "ereport(" in lines[i])
    depth = 0
    for end in range(start, len(lines)):
        depth += lines[end].count("(") - lines[end].count(")")
        if depth <= 0:
            return list(range(start + 1, end + 2))
    raise ValueError("unbalanced ereport")


def fetch(tag: str, cache: Path) -> tuple[str, str, list[int]]:
    for path in PATHS:
        name = path.rsplit("/", 1)[1]
        dest = cache / f"{tag}__{name}"
        if not dest.exists():
            try:
                with urllib.request.urlopen(RAW.format(tag=tag, path=path), timeout=60) as r:
                    dest.write_bytes(r.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    continue
                raise
        source = dest.read_text(encoding="latin-1")
        if "unsupported frontend protocol" in source:
            return version_name(tag), name, error_lines(source)
    raise LookupError(f"no startup error found in {tag}")


def main(cache: Path) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda tag: fetch(tag, cache), release_tags()))

    table: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for version, name, lines in results:
        for line in lines:
            table[name][str(line)].append(version)
    OUT.write_text(json.dumps(table, indent=0, sort_keys=True) + "\n")
    print(f"{len(results)} releases -> {OUT}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
