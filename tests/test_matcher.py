"""Matching scanned services to CVEs, against a small handmade NVD."""

import pytest

from dingdongditch import db, matcher
from dingdongditch.nmap_parser import Service


def cpe(vendor, product, version="*", update="*"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"


ROWS = [
    # cve, cpe, start_including, start_excluding, end_including, end_excluding
    ("CVE-EXACT", cpe("samba", "samba", "3.0.20"), None, None, None, None),
    ("CVE-RANGE", cpe("samba", "samba"), "3.0.0", None, None, "3.0.25"),
    ("CVE-RANGE", cpe("samba", "samba"), "3.2.0", None, None, "3.2.13"),  # another branch
    ("CVE-LATER", cpe("samba", "samba"), "3.0.21", None, "3.0.24", None),
    ("CVE-UPDATE", cpe("samba", "samba", "3.0.20", "a"), None, None, None, None),
    ("CVE-ANY", cpe("samba", "samba"), None, None, None, None),
    ("CVE-NOVERSION", cpe("samba", "samba", "-"), None, None, None, None),
    ("CVE-REJECTED", cpe("samba", "samba", "3.0.20"), None, None, None, None),
    ("CVE-OTHER", cpe("other", "samba", "3.0.20"), None, None, None, None),
    ("CVE-SSH", cpe("openbsd", "openssh", "4.7"), None, None, None, None),
    ("CVE-SSH-P1", cpe("openbsd", "openssh", "4.7", "p1"), None, None, None, None),
    ("CVE-SSH-OLD", cpe("openbsd", "openssh"), None, None, None, "4.4"),
    ("CVE-PG-SOME", cpe("postgresql", "postgresql"), "8.3.0", None, None, "8.3.5"),
    ("CVE-PG-ALL", cpe("postgresql", "postgresql"), "8.3.0", None, None, "8.3.8"),
    ("CVE-PG-OLD", cpe("postgresql", "postgresql", "8.2.4"), None, None, None, None),
    ("CVE-FTP-BACKDOOR", cpe("vsftpd_project", "vsftpd", "2.3.4"), None, None, None, None),
    ("CVE-FTP-OLD", cpe("beasts", "vsftpd"), None, None, "2.3.4", None),
    # Zerologon's shape: "before 4.10.18" with no start, then two newer branches.
    ("CVE-ZERO", cpe("samba", "samba"), None, None, None, "4.10.18"),
    ("CVE-ZERO", cpe("samba", "samba"), "4.11.0", None, None, "4.11.13"),
    ("CVE-ZERO", cpe("samba", "samba"), "4.12.0", None, None, "4.12.7"),
    # Filed twice: once exactly, once open-ended under another vendor name.
    ("CVE-FTP-BOTH", cpe("vsftpd_project", "vsftpd", "2.3.4"), None, None, None, None),
    ("CVE-FTP-BOTH", cpe("beasts", "vsftpd"), None, None, None, "3.0"),
]


@pytest.fixture
def con():
    connection = db.connect(":memory:")
    cves = {row[0] for row in ROWS}
    connection.executemany(
        "INSERT INTO cve (id, published, last_modified, status, description) "
        "VALUES (?, 'p', 'm', ?, 'd')",
        [(cve, "Rejected" if cve == "CVE-REJECTED" else "Analyzed") for cve in cves],
    )
    connection.executemany(
        "INSERT INTO cve_cpe VALUES (?, 'a', ?, ?, ?, ?, ?, ?, ?)",
        [
            (cve, *matcher._CPE_SPLIT.split(name)[3:5], name, *limits)
            for cve, name, *limits in ROWS
        ],
    )
    yield connection
    connection.close()


def ids(matches):
    return [m.cve_id for m in matches]


def test_exact_versions_and_ranges(con):
    found = matcher.match_versions(con, "samba", "samba", ["3.0.20"])
    assert ids(found) == ["CVE-ANY", "CVE-EXACT", "CVE-RANGE", "CVE-ZERO"]
    assert all(m.certain for m in found)
    fixes = {m.cve_id: m.fixed_in for m in found}
    assert fixes == {
        "CVE-ANY": None, "CVE-EXACT": None, "CVE-RANGE": "3.0.25", "CVE-ZERO": "4.10.18",
    }


def test_a_range_with_no_first_release_is_only_a_possible_match(con):
    # Samba 3.0.20 against "before 4.10.18": NVD doesn't say where the bug began.
    old = {m.cve_id: m for m in matcher.match_versions(con, "samba", "samba", ["3.0.20"])}
    assert old["CVE-ZERO"].open_ended
    assert old["CVE-ANY"].open_ended  # "every version" names no start either
    assert not old["CVE-EXACT"].open_ended  # NVD names 3.0.20 itself
    assert not old["CVE-RANGE"].open_ended  # from 3.0.0
    # 4.11.5 is inside a branch that starts at 4.11.0, so there it is a sure match.
    [newer] = [m for m in matcher.match_versions(con, "samba", "samba", ["4.11.5"])
               if m.cve_id == "CVE-ZERO"]
    assert (newer.open_ended, newer.fixed_in) == (False, "4.11.13")
    # An end-including limit with no start is open-ended too.
    [ssh] = matcher.match_versions(con, "openbsd", "openssh", ["4.3"])
    assert ssh.open_ended


def test_one_sure_row_makes_the_whole_match_sure(con):
    svc = Service("h", 21, "tcp", "open", product="vsftpd", version="2.3.4",
                  cpes=["cpe:/a:vsftpd:vsftpd:2.3.4"])
    found = {m.cve_id: m for m in matcher.match_service(con, svc)}
    assert not found["CVE-FTP-BOTH"].open_ended  # exact under one name, open under another
    assert found["CVE-FTP-OLD"].open_ended


def test_update_field_is_part_of_the_version(con):
    assert "CVE-UPDATE" in ids(matcher.match_versions(con, "samba", "samba", ["3.0.20a"]))
    assert "CVE-EXACT" not in ids(matcher.match_versions(con, "samba", "samba", ["3.0.21"]))


def test_fix_comes_from_the_branch_that_matched(con):
    [match] = [
        m for m in matcher.match_versions(con, "samba", "samba", ["3.2.5"])
        if m.cve_id == "CVE-RANGE"
    ]
    assert match.fixed_in == "3.2.13"


def test_openssh_patch_counts_as_its_release(con):
    found = ids(matcher.match_versions(con, "openbsd", "openssh", ["4.7p1"]))
    assert found == ["CVE-SSH", "CVE-SSH-P1"]
    assert ids(matcher.match_versions(con, "openbsd", "openssh", ["4.7p2"])) == ["CVE-SSH"]
    assert ids(matcher.match_versions(con, "openbsd", "openssh", ["4.3"])) == ["CVE-SSH-OLD"]


@pytest.mark.parametrize(
    "version, release, patch",
    [
        ("4.7p1", "4.7", True),
        ("9.4.2-P1", "9.4.2", True),
        ("5.0.51a", "5.0.51", True),
        ("2.0rc1", "2.0", False),
        ("4.7.1", "4.7", False),
        ("4.71", "4.7", False),
        ("4.7p1", "4.7beta", False),
    ],
)
def test_patch_of(version, release, patch):
    assert matcher._patch_of(version, release) is patch


def test_several_possible_releases_mark_partial_matches(con):
    versions = matcher._expand("8.3.0-8.3.7")
    assert versions == [f"8.3.{n}" for n in range(8)]
    found = {m.cve_id: m for m in matcher.match_versions(con, "postgresql", "postgresql", versions)}
    assert set(found) == {"CVE-PG-SOME", "CVE-PG-ALL"}
    assert found["CVE-PG-ALL"].certain
    assert not found["CVE-PG-SOME"].certain


def test_targets_come_from_the_service_cpes():
    svc = Service("h", 22, "tcp", "open", "ssh", "OpenSSH", "4.7p1 Debian 8ubuntu1",
                  cpes=["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"])
    assert matcher.targets(svc) == [("openbsd", "openssh", ["4.7p1"])]
    svc.cpes = ["cpe:/a:openbsd:openssh"]  # no version in the CPE: use the service's
    assert matcher.targets(svc) == [("openbsd", "openssh", ["4.7p1"])]
    svc.version = ""
    assert matcher.targets(svc) == []  # no version: nothing can be matched


def test_postgres_branch_becomes_its_possible_releases():
    svc = Service("h", 5432, "tcp", "open", "postgresql", "PostgreSQL", "8.3",
                  extrainfo="one of 8.3.0-8.3.7", cpes=["cpe:/a:postgresql:postgresql:8.3"])
    [(vendor, product, versions)] = matcher.targets(svc)
    assert versions == [f"8.3.{n}" for n in range(8)]
    svc.extrainfo = "one of 9.0.1, 9.1.0-9.1.2"
    assert matcher.targets(svc)[0][2] == ["9.0.1", "9.1.0", "9.1.1", "9.1.2"]


def test_match_service_end_to_end(con):
    svc = Service("h", 445, "tcp", "open", "microsoft-ds", "Samba smbd", "3.0.20",
                  cpes=["cpe:/a:samba:samba:3.0.20"])
    found = ids(matcher.match_service(con, svc))
    assert found == ["CVE-ANY", "CVE-EXACT", "CVE-RANGE", "CVE-ZERO"]
    svc.cpes = []
    assert matcher.match_service(con, svc) == []


def test_last_affected_release_when_nvd_names_no_fix(con):
    [later] = [m for m in matcher.match_versions(con, "samba", "samba", ["3.0.22"])
               if m.cve_id == "CVE-LATER"]
    assert (later.fixed_in, later.last_affected) == (None, "3.0.24")


def test_other_vendor_names_for_the_same_product(con):
    assert matcher.same_product("vsftpd", "vsftpd") == [
        ("vsftpd", "vsftpd"), ("beasts", "vsftpd"), ("vsftpd_project", "vsftpd"),
    ]
    assert matcher.same_product("samba", "samba") == [("samba", "samba")]
    # nmap names vsftpd "vsftpd:vsftpd"; NVD uses neither of those vendor names.
    svc = Service("h", 21, "tcp", "open", product="vsftpd", version="2.3.4",
                  cpes=["cpe:/a:vsftpd:vsftpd:2.3.4"])
    found = matcher.match_service(con, svc)
    assert ids(found) == ["CVE-FTP-BACKDOOR", "CVE-FTP-BOTH", "CVE-FTP-OLD"]
    assert found[2].last_affected == "2.3.4"
