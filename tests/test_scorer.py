"""Scoring and explaining matched CVEs, with a model trained on a small made-up NVD."""

import pytest
import risk_world

from dingdongditch import db, scorer
from dingdongditch.matcher import Match
from dingdongditch.nmap_parser import Service


@pytest.fixture(scope="module")
def world():
    con = db.connect(":memory:")
    saved = risk_world.fill(con)
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
    assert boring.rule is None and risky.rule is None
    assert (risky.certain, risky.fixed_in, risky.epss, risky.cvss) == (False, "2.0", 0.42, 9.8)
    assert risky.summary == "Remote gateway takeover"
    assert 0 < len(risky.reasons) <= scorer.REASONS
    assert any("gateway" in reason or "OS command" in reason for reason in risky.reasons)
    assert scorer.worst(results) == "KNOWN EXPLOITED"
    assert scorer.worst(results[1:]) == risky.level
    assert scorer.worst([]) is None


def test_public_remote_exploit_makes_it_at_least_high(world):
    con, saved = world
    matches = [Match(cve, certain=True, fixed_in=None) for cve in ("CVE-002", "CVE-003")]
    remote, local = scorer.Scorer(con, saved).score(matches)
    assert remote.cve_id == "CVE-002"
    assert (remote.level, remote.rule) == ("HIGH", scorer.REMOTE_EXPLOIT_RULE)
    assert (local.level, local.rule) == ("LOW", None)  # local exploits don't count


def test_score_services_keeps_each_ports_own_match(world):
    con, saved = world

    def gateway(port, version, extrainfo=""):
        return Service("10.0.0.1", port, "tcp", "open", product="gateway", version=version,
                       extrainfo=extrainfo, cpes=[f"cpe:/a:acme:gateway:{version}"])

    old, unsure, new, unknown = scorer.Scorer(con, saved).score_services([
        gateway(1, "1.5"),
        gateway(2, "2", extrainfo="one of 1.9, 2.1"),  # only 1.9 is affected
        gateway(3, "2.0"),
        Service("10.0.0.1", 4, "tcp", "open", name="ssh"),
    ])
    assert len(old) == len(unsure) == 12 and new == unknown == []
    assert old[0].level == "KNOWN EXPLOITED"
    assert all(s.certain for s in old) and not any(s.certain for s in unsure)
    assert {s.fixed_in for s in old} == {"2.0"}


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


def test_remote_exploit_raises_but_never_lowers():
    assert scorer.level_for(False, 0.5, remote_exploit=True) == "HIGH"
    assert scorer.level_for(False, 0.96, remote_exploit=True) == "HIGH"
    assert scorer.level_for(True, 0.5, remote_exploit=True) == "KNOWN EXPLOITED"


@pytest.mark.parametrize(
    "description, summary",
    [
        ("Remote takeover. More.", "Remote takeover"),
        ("An issue was discovered in Foo 1.2. A long name crashes it.", "A long name crashes it."),
        ("An issue was discovered in Foo 1.2", "An issue was discovered in Foo 1.2"),
        ("x" * 200, "x" * 107 + "..."),
    ],
)
def test_summary(description, summary):
    assert scorer._summary(description) == summary
