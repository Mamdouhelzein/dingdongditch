"""A small made-up NVD with a model trained on it, for the scoring tests.

60 CVEs: every fifth one is a risky 'gateway' CVE (acme gateway before 2.0), the
others are boring printer CVEs (printco printer 1.0 only). Most risky ones are
already on CISA's list.
"""

from datetime import date, timedelta

from dingdongditch import features, train

V3_EASY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_HARD = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
GATEWAY = "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*"
PRINTER = "cpe:2.3:a:printco:printer:1.0:*:*:*:*:*:*:*"


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
        "INSERT INTO cve_cpe (cve_id, part, vendor, product, cpe, version_end_excluding) "
        "VALUES (?, 'a', ?, ?, ?, ?)",
        [
            (cve[0], "acme", "gateway", GATEWAY, "2.0") if "gateway" in cve[2]
            else (cve[0], "printco", "printer", PRINTER, None)
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
