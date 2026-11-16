"""A small made-up NVD with a model trained on it, for the scoring tests.

60 CVEs: every fifth one is a risky 'gateway' CVE (acme gateway from 1.0 up to 2.0),
the others are boring printer CVEs (printco printer 1.0 only). Most risky ones are
already on CISA's list.

add_open_ended() then adds NVD rows with no first affected release, which only
ever match as possible.
"""

from datetime import date, timedelta

from dingdongditch import features, train

V3_EASY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_HARD = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
GATEWAY = "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*"
PRINTER = "cpe:2.3:a:printco:printer:1.0:*:*:*:*:*:*:*"
ROUTER = "cpe:2.3:a:netco:router:*:*:*:*:*:*:*:*"
_CPE_ROW = (
    "INSERT INTO cve_cpe (cve_id, part, vendor, product, cpe, version_start_including, "
    "version_end_excluding) VALUES (?, 'a', ?, ?, ?, ?, ?)"
)


def fill(con) -> dict:
    """Fill an empty database and return the saved-model dict trained on it."""
    cves, kev = [], []
    for n in range(60):
        risky = n % 5 == 0
        cves.append((
            f"CVE-{n:03}",
            "2020-01-01T00:00:00.000",
            "Remote gateway takeover. More text." if risky else "Minor printer glitch. More.",
            9.8 if risky else 3.1,
            V3_EASY if risky else V3_HARD,
            "CWE-78" if risky else "CWE-79",
        ))
        if risky and n < 40:
            kev.append((f"CVE-{n:03}", "2021-01-01"))
    con.executemany(
        "INSERT INTO cve (id, published, last_modified, status, description, cvss3_score, "
        "cvss3_vector, cvss2_score, cvss2_vector, cwes) "
        "VALUES (?, ?, 'm', 'Analyzed', ?, ?, ?, 5.0, 'AV:N/AC:L/Au:N/C:P/I:P/A:P', ?)",
        cves,
    )
    con.executemany(
        _CPE_ROW,
        [
            (cve[0], "acme", "gateway", GATEWAY, "1.0", "2.0") if "gateway" in cve[2]
            else (cve[0], "printco", "printer", PRINTER, None, None)
            for cve in cves
        ],
    )
    con.executemany("INSERT INTO kev VALUES (?, 'v', 'p', 'n', ?, 'Unknown')", kev)
    con.execute("INSERT INTO epss VALUES ('CVE-045', 0.42, 0.99)")
    # A boring CVE with an old public remote exploit, and one with only a local exploit.
    con.execute("INSERT INTO exploitdb VALUES (1, 'CVE-002', '2010-01-01', 'remote', 'unix', 1)")
    con.execute("INSERT INTO exploitdb VALUES (2, 'CVE-003', '2010-01-01', 'local', 'unix', 1)")
    con.commit()
    today = date.today() + timedelta(days=1)
    frame = features.load(con, today)
    model = train.fit(frame, today, train.DEFAULT, min_count=1)
    return {"model": model, "spread": train.score_spread(model, frame)}


def add_open_ended(con) -> None:
    """Rows that say "every release before X", for a database fill() already filled.

    The boring CVE-007 for every gateway before 3.0, and for every netco router
    before 9.0 the listed CVE-005 and the boring CVE-006. Added after training, so
    the model is the same one the other tests use.
    """
    con.executemany(
        _CPE_ROW,
        [
            ("CVE-007", "acme", "gateway", GATEWAY, None, "3.0"),
            ("CVE-005", "netco", "router", ROUTER, None, "9.0"),
            ("CVE-006", "netco", "router", ROUTER, None, "9.0"),
        ],
    )
    con.commit()
