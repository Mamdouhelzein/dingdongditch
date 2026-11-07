"""Scoring and explaining matched CVEs, with a model trained on a small made-up NVD."""

from datetime import date, timedelta

import pytest

from dingdongditch import db, features, scorer, train
from dingdongditch.matcher import Match

V3_EASY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_HARD = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"


@pytest.fixture(scope="module")
def world():
    """60 CVEs: the 'gateway' ones get exploited, a few are already on CISA's list."""
    con = db.connect(":memory:")
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
        "INSERT INTO cve_cpe (cve_id, part, vendor, product, cpe) VALUES (?, 'a', ?, ?, 'x')",
        [(cve[0], *(("acme", "gateway") if "gateway" in cve[2] else ("printco", "printer")))
         for cve in cves],
    )
    con.executemany("INSERT INTO kev VALUES (?, 'v', 'p', 'n', ?, 'Unknown')", kev)
    con.execute("INSERT INTO epss VALUES ('CVE-045', 0.42, 0.99)")
    today = date.today() + timedelta(days=1)
    frame = features.load(con, today)
    model = train.fit(frame, today, train.DEFAULT, min_count=1)
    saved = {"model": model, "spread": train.score_spread(model, frame)}
    yield con, saved
    con.close()


def test_scores_levels_reasons_and_order(world):
    con, saved = world
    matches = [
        Match("CVE-001", certain=True, fixed_in=None),  # boring
        Match("CVE-045", certain=False, fixed_in="2.0"),  # risky, not listed yet
        Match("CVE-005", certain=True, fixed_in="1.5"),  # risky, already listed
        Match("CVE-999", certain=True, fixed_in=None),  # not in the database
    ]
    results = scorer.Scorer(con, saved).score(matches)
    assert [r.cve_id for r in results] == ["CVE-005", "CVE-045", "CVE-001"]  # worst first
    listed, risky, boring = results
    assert listed.level == "KNOWN EXPLOITED"
    # A fifth of this small world is risky, so "top 1%" is too narrow to test here.
    assert risky.riskier_than >= 0.75 > boring.riskier_than
    assert boring.level == "LOW"
    assert (risky.certain, risky.fixed_in, risky.epss, risky.cvss) == (False, "2.0", 0.42, 9.8)
    assert risky.summary == "Remote gateway takeover"
    assert 0 < len(risky.reasons) <= scorer.REASONS
    assert any("gateway" in reason or "OS command" in reason for reason in risky.reasons)
    assert scorer.worst(results) == "KNOWN EXPLOITED"
    assert scorer.worst(results[1:]) == risky.level
    assert scorer.worst([]) is None


def test_nothing_to_score(world):
    con, saved = world
    assert scorer.Scorer(con, saved).score([]) == []


def test_old_model_file_is_refused(world):
    con, saved = world
    with pytest.raises(scorer.ModelError, match="train"):
        scorer.Scorer(con, {"model": saved["model"]})


def test_open_explains_what_is_missing(tmp_path):
    with pytest.raises(scorer.ModelError, match="update-db"):
        scorer.Scorer.open(tmp_path / "none.db", tmp_path / "none.joblib")
    db.connect(tmp_path / "v.db").close()
    with pytest.raises(scorer.ModelError, match="dingdongditch train"):
        scorer.Scorer.open(tmp_path / "v.db", tmp_path / "none.joblib")
    (tmp_path / "bad.joblib").write_bytes(b"not a model")
    with pytest.raises(scorer.ModelError, match="Can't read the model"):
        scorer.Scorer.open(tmp_path / "v.db", tmp_path / "bad.joblib")


@pytest.mark.parametrize(
    "name, value, words",
    [
        ("cvss__PR=N", 1, "no login needed"),
        ("cvss__AV=N", 1, "reachable over the network"),
        ("cvss__AV=P", 1, None),  # physical access is not a reason to worry more
        ("cwe__CWE-78", 1, "OS command injection (CWE-78)"),
        ("cwe__CWE-1321", 1, "weakness CWE-1321"),
        ("product__ivanti", 1, "affects ivanti products"),
        ("product__samba:samba", 1, "affects samba (samba)"),
        ("text__exploited wild", 0.3, 'description says "exploited wild"'),
        ("text__exploited wild", 0, None),
        ("number__log_exploits", 1.4, "public exploit on Exploit-DB"),
        ("number__log_exploits", -0.2, None),  # below average: no exploit
    ],
)
def test_describe(name, value, words):
    assert scorer.describe(name, value) == words


@pytest.mark.parametrize(
    "listed, share, level",
    [(True, 0.1, "KNOWN EXPLOITED"), (False, 0.995, "HIGH"), (False, 0.96, "MEDIUM"),
     (False, 0.5, "LOW")],
)
def test_level_for(listed, share, level):
    assert scorer.level_for(listed, share) == level
