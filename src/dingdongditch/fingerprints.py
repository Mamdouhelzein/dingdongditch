"""Turn a banner into service name, product, version and CPE.

e.g. "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7" -> ssh / OpenSSH / 7.4p1 /
cpe:/a:openbsd:openssh:7.4p1. CPE vendor:product names follow NVD so the
CVE matcher can look them up directly.

Banners come from probes.clean_banner, so non-printable bytes appear as
literal "\\xNN" text, which some patterns below rely on.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from dingdongditch.nmap_parser import Service


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern[str]
    name: str
    product: str = ""
    cpe: str = ""  # "vendor:product" in NVD's naming; the version is appended if found


def _r(regex: str, name: str, product: str = "", cpe: str = "") -> Rule:
    return Rule(re.compile(regex, re.MULTILINE), name, product, cpe)


_V = r"(?P<version>\d+(?:\.\d+)+[\w.-]*)"  # 2.4.49, 7.4p1, 10.3.27
_ESC = r"(?:\\x[0-9a-f]{2}|\s)+"            # binary bytes (escaped, or tab/newline)

# Checked in order, first match wins. Optional named groups: version, extra.
RULES: list[Rule] = [
    # SSH
    _r(r"^SSH-[\d.]+-OpenSSH_(?P<version>[\w.]+)(?:[ -](?P<extra>.+))?$",
       "ssh", "OpenSSH", "openbsd:openssh"),
    _r(r"^SSH-[\d.]+-dropbear_(?P<version>[\w.]+)", "ssh", "Dropbear sshd",
       "dropbear_ssh_project:dropbear_ssh"),
    _r(r"^SSH-[\d.]+-(?P<extra>\S+)", "ssh"),
    # FTP
    _r(r"^220 \(vsFTPd " + _V + r"\)", "ftp", "vsftpd", "vsftpd_project:vsftpd"),
    _r(r"^220[ -].*ProFTPD " + _V, "ftp", "ProFTPD", "proftpd:proftpd"),
    _r(r"^220[ -].*Pure-FTPd", "ftp", "Pure-FTPd", "pureftpd:pure-ftpd"),
    _r(r"^220[ -].*FileZilla Server(?: version)? " + _V, "ftp", "FileZilla ftpd",
       "filezilla-project:filezilla_server"),
    _r(r"^220[ -].*\bFTP\b", "ftp"),
    # Mail
    _r(r"^220 .*ESMTP Postfix", "smtp", "Postfix smtpd", "postfix:postfix"),
    _r(r"^220 .*Exim " + _V, "smtp", "Exim smtpd", "exim:exim"),
    _r(r"^220 .*Sendmail " + _V, "smtp", "Sendmail", "sendmail:sendmail"),
    _r(r"^220 .*SMTP", "smtp"),
    _r(r"^\* OK .*Dovecot", "imap", "Dovecot imapd", "dovecot:dovecot"),
    _r(r"^\+OK .*Dovecot", "pop3", "Dovecot pop3d", "dovecot:dovecot"),
    _r(r"^\* OK", "imap"),
    _r(r"^\+OK", "pop3"),
    # Databases and caches. MySQL's greeting: binary length, protocol 10 ("\n"), version.
    _r(r"\\x00\n5\.5\.5-" + _V + r"-MariaDB", "mysql", "MariaDB", "mariadb:mariadb"),
    _r(r"\\x00\n" + _V + r"-MariaDB", "mysql", "MariaDB", "mariadb:mariadb"),
    _r(r"\\x00\n(?P<version>\d+\.\d+\.\d+[a-z]?)", "mysql", "MySQL", "oracle:mysql"),
    _r(r"is not allowed to connect to this M(?:ySQL|ariaDB) server", "mysql", "MySQL"),
    _r(r"^redis_version:" + _V, "redis", "Redis", "redis:redis"),
    _r(r"^-(?:NOAUTH|DENIED|ERR operation not permitted)", "redis", "Redis"),
    # Message brokers. ActiveMQ OpenWire sends its WireFormatInfo first.
    _r(r"ActiveMQ[\s\S]*?ProviderVersion" + _ESC + _V, "activemq", "Apache ActiveMQ",
       "apache:activemq"),
    _r(r"\\x01ActiveMQ", "activemq", "Apache ActiveMQ", "apache:activemq"),
    _r(r"^AMQP", "amqp"),
    # Remote access. A bare shell prompt with no login at all; it matches nothing else.
    _r(r"^[\w.-]+@[\w.-]+:\S*[#$]$", "bindshell"),
    _r(r"Where are you\?", "exec", "netkit-rsh rexecd"),
    _r(r"^RFB (?P<extra>\d{3}\.\d{3})", "vnc"),
    _r(r"^\\xff\\xf[b-e]", "telnet"),  # telnet option negotiation (IAC WILL/WONT/DO/DONT)
    # HTTP/2-only servers (often gRPC) open with a SETTINGS frame:
    # 3-byte length, type 0x04, flags 0, stream 0.
    _r(r"^\\x00(?:\\x[0-9a-f]{2}|.){2}\\x04\\x00\\x00\\x00\\x00\\x00", "http2"),
    # DNS servers answering our version.bind question (binary_probes.py).
    # "9.11.5-P4-5.1+deb10u5-Debian": the version is "9.11.5-P4", the rest is packaging.
    _r(r"^version\.bind: (?P<version>9\.\d+\.\d+(?:-P\d+)?)-?(?P<extra>\S*)", "domain",
       "ISC BIND", "isc:bind"),
    _r(r"^version\.bind: dnsmasq-" + _V, "domain", "dnsmasq", "thekelleys:dnsmasq"),
    _r(r"^version\.bind: unbound " + _V, "domain", "Unbound", "nlnetlabs:unbound"),
    _r(r"^version\.bind: PowerDNS Authoritative Server " + _V, "domain",
       "PowerDNS Authoritative Server", "powerdns:authoritative"),
    _r(r"^version\.bind:", "domain"),  # a DNS server that keeps its version to itself
    # IRC, once registered (conversations.py): "Your host is X, running version Y".
    _r(r"^:\S+ 002 .*running version Unreal(?:IRCd-)?" + _V, "irc", "UnrealIRCd",
       "unrealircd:unrealircd"),
    _r(r"^:\S+ 002 .*running version InspIRCd-(?P<version>\d+(?:\.\d+)*)", "irc", "InspIRCd",
       "inspircd:inspircd"),
    _r(r"^:\S+ 002 .*running version ngircd-(?P<version>\d+(?:\.\d+)*)", "irc", "ngIRCd",
       "barton:ngircd"),
    _r(r"^:\S+ 002 .*running version hybrid-" + _V, "irc", "ircd-hybrid"),
    _r(r"^:\S+ 002 .*running version ircd-ratbox-" + _V, "irc", "ircd-ratbox"),
    _r(r"^:\S+ 002 .*running version (?P<extra>\S+)", "irc"),
    # SMB, after an anonymous session setup (conversations.py).
    _r(r"^smb lan manager: Samba (?P<version>\d+\.\d+\.\d+[a-z]?)-?(?P<extra>\S*)", "smb",
       "Samba smbd", "samba:samba"),
    _r(r"^smb native os: (?P<extra>Windows.+)$", "smb", "Microsoft Windows SMB"),
    _r(r"^smb (?:native os|lan manager|domain):", "smb"),
    # Other
    _r(r"^:\S+ NOTICE AUTH\b", "irc"),
    _r(r"VMware Authentication Daemon Version " + _V, "vmware-auth",
       "VMware Authentication Daemon"),
]

# Web servers, matched against the HTTP "Server:" header.
SERVER_RULES: list[Rule] = [
    _r(r"^Apache-Coyote", "http", "Apache Tomcat", "apache:tomcat"),
    _r(r"^Apache(?:/" + _V + r")?(?: \((?P<extra>[^)]+)\))?", "http", "Apache httpd",
       "apache:http_server"),
    _r(r"^nginx(?:/" + _V + ")?", "http", "nginx", "nginx:nginx"),
    _r(r"^Microsoft-IIS(?:/" + _V + ")?", "http", "Microsoft IIS httpd",
       "microsoft:internet_information_services"),
    _r(r"^lighttpd(?:/" + _V + ")?", "http", "lighttpd", "lighttpd:lighttpd"),
    _r(r"^Jetty\((?P<version>[\w.-]+)\)", "http", "Jetty", "eclipse:jetty"),
    _r(r"^Werkzeug(?:/" + _V + ")?", "http", "Werkzeug httpd", "palletsprojects:werkzeug"),
    _r(r"^gunicorn(?:/" + _V + ")?", "http", "gunicorn", "gunicorn:gunicorn"),
    _r(r"^MiniServ(?:/" + _V + ")?", "http", "Webmin httpd", "webmin:webmin"),
    _r(r"^CouchDB(?:/" + _V + ")?", "http", "CouchDB httpd", "apache:couchdb"),
    _r(r"^Docker(?:/" + _V + ")?", "docker", "Docker", "docker:docker"),
    _r(r"^squid(?:/" + _V + ")?", "http-proxy", "Squid http proxy", "squid-cache:squid"),
]

# App-specific HTTP headers win over the Server header (Jenkins runs on Jetty, etc.).
HEADER_RULES: dict[str, Rule] = {
    "x-jenkins": _r(r"^" + _V, "http", "Jenkins", "jenkins:jenkins"),
}


@dataclass
class Fingerprint:
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: list[str] | None = None


def _apply(rule: Rule, text: str) -> Fingerprint | None:
    m = rule.pattern.search(text)
    if not m:
        return None
    groups = m.groupdict()
    version = groups.get("version") or ""
    cpe = f"cpe:/a:{rule.cpe}" + (f":{version}" if version else "") if rule.cpe else ""
    return Fingerprint(
        name=rule.name,
        product=rule.product,
        version=version,
        extrainfo=(groups.get("extra") or "").strip(),
        cpes=[cpe] if cpe else [],
    )


def _headers(banner: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in banner.splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers.setdefault(key.strip().lower(), value.strip())
    return headers


def _identify_http(banner: str) -> Fingerprint:
    headers = _headers(banner)
    fp = None
    for header, rule in HEADER_RULES.items():
        if header in headers and (fp := _apply(rule, headers[header])):
            break
    server = headers.get("server", "")
    if fp is None and server:
        for rule in SERVER_RULES:
            if fp := _apply(rule, server):
                break
        else:
            # Unknown server: keep what it calls itself, but no CPE.
            m = re.match(r"(?P<product>[^/\s]+)(?:/(?P<version>\S+))?", server)
            if m:
                fp = Fingerprint("http", m["product"], m["version"] or "", cpes=[])
    fp = fp or Fingerprint("http", cpes=[])
    powered_by = headers.get("x-powered-by")
    if powered_by:
        fp.extrainfo = "; ".join(x for x in (fp.extrainfo, powered_by) if x)
    return fp


# --- PostgreSQL: the source line its startup error came from -> releases ---
# Built from PostgreSQL's own source by scripts/make_postgres_lines.py.

_PG_SOURCE = re.compile(r" \((?P<file>[\w.]+):(?P<line>\d+)\b[^()]*\)$")


@lru_cache(maxsize=1)
def _postgres_lines() -> dict[str, dict[str, list[str]]]:
    table = resources.files("dingdongditch").joinpath("data/postgres_lines.json")
    return json.loads(table.read_text(encoding="utf-8"))


def _version_runs(versions: Iterable[str]) -> list[tuple[int, ...]]:
    """Releases as sorted (first, last) runs: 8.3.0, 8.3.1, 8.3.2, 8.4.1 -> 2 runs."""
    runs: list[list[tuple[int, ...]]] = []
    for key in sorted({tuple(int(x) for x in v.split(".")) for v in versions}):
        last = runs[-1][1] if runs else None
        if last and last[:-1] == key[:-1] and last[-1] + 1 == key[-1]:
            runs[-1][1] = key
        else:
            runs.append([key, key])
    return [tuple(run) for run in runs]


def _identify_postgres(banner: str) -> Fingerprint:
    """PostgreSQL, with the version if its error's source line pins one down.

    One line can be shared by several releases: then the version is the branch
    they share (e.g. 8.3), and extrainfo lists the exact candidates.
    """
    m = _PG_SOURCE.search(banner)
    versions = _postgres_lines().get(m["file"], {}).get(m["line"], []) if m else []
    if not versions:
        return Fingerprint("postgresql", "PostgreSQL", cpes=["cpe:/a:postgresql:postgresql"])

    def name(key: tuple[int, ...]) -> str:
        return ".".join(map(str, key))

    runs = _version_runs(versions)
    # A branch is 8.3 before PostgreSQL 10, and just 10, 11, ... after.
    branches = {first[: 2 if first[0] < 10 else 1] for first, _ in runs}
    if len(runs) == 1 and runs[0][0] == runs[0][1]:
        version, extra = name(runs[0][0]), ""
    else:
        version = name(branches.pop()) if len(branches) == 1 else ""
        extra = "one of " + ", ".join(
            name(first) if first == last else f"{name(first)}-{name(last)}" for first, last in runs
        )
    cpe = "cpe:/a:postgresql:postgresql" + (f":{version}" if version else "")
    return Fingerprint("postgresql", "PostgreSQL", version, extra, [cpe])


def identify(banner: str) -> Fingerprint | None:
    """Work out what a service is from its banner, or None if we can't tell."""
    if not banner:
        return None
    if "access MongoDB over HTTP" in banner:  # MongoDB's HTTP-looking answer to our HEAD
        return Fingerprint("mongodb", "MongoDB", cpes=["cpe:/a:mongodb:mongodb"])
    if re.match(r"HTTP/\d(?:\.\d)? \d{3}", banner):
        return _identify_http(banner)
    if banner.startswith("postgresql error: "):  # our PostgreSQL probe's answer
        return _identify_postgres(banner)
    for rule in RULES:
        if fp := _apply(rule, banner):
            return fp
    return None


def fingerprint(services: Iterable[Service]) -> list[Service]:
    """Fill in name / product / version / extrainfo / cpes from each banner.

    Services we can't identify keep their default name from ports.py.
    """
    services = list(services)
    for svc in services:
        fp = identify(svc.banner)
        if fp:
            svc.name = fp.name
            svc.product, svc.version, svc.extrainfo = fp.product, fp.version, fp.extrainfo
            svc.cpes = fp.cpes or []
        if svc.tls and svc.name == "http":
            svc.name = "https"
    return services


# --- Karen mode: the app behind the web server -------------------------------
# A port that only said "Jetty" or "Apache" is often Jenkins, Tomcat, Solr, ...
# These rules look at the home page's <title>, headers and body.

TITLE_RULES: list[Rule] = [
    _r(r"Apache Tomcat(?:/" + _V + ")?", "http", "Apache Tomcat", "apache:tomcat"),
    _r(r"\[Jenkins\]|^Jenkins\b", "http", "Jenkins", "jenkins:jenkins"),
    _r(r"Struts2? Showcase", "http", "Apache Struts", "apache:struts"),
    _r(r"Solr Admin", "http", "Apache Solr", "apache:solr"),
    _r(r"Apache ActiveMQ", "http", "Apache ActiveMQ", "apache:activemq"),
    _r(r"phpMyAdmin", "http", "phpMyAdmin", "phpmyadmin:phpmyadmin"),
    _r(r"\bKibana\b", "http", "Kibana", "elastic:kibana"),
    _r(r"\bGrafana\b", "http", "Grafana", "grafana:grafana"),
    _r(r"\bGitLab\b", "http", "GitLab", "gitlab:gitlab"),
    _r(r"\bWebmin\b", "http", "Webmin", "webmin:webmin"),
    _r(r"\bConfluence\b", "http", "Atlassian Confluence", "atlassian:confluence"),
    _r(r"\bJira\b", "http", "Atlassian Jira", "atlassian:jira"),
    _r(r"Nexus Repository Manager", "http", "Nexus Repository Manager",
       "sonatype:nexus_repository_manager"),
    _r(r"\bThinkPHP\b", "http", "ThinkPHP", "thinkphp:thinkphp"),
]

APP_HEADER_RULES: dict[str, Rule] = {
    "x-jenkins": HEADER_RULES["x-jenkins"],
    "x-generator": _r(r"^Drupal (?P<version>\d+)", "http", "Drupal", "drupal:drupal"),
}

BODY_RULES: list[Rule] = [
    # Elasticsearch answers GET / with JSON: {"version": {"number": "1.4.2", "lucene_version": ...
    _r(r'"number"\s*:\s*"' + _V + r'"[\s\S]*"lucene_version"', "http", "Elasticsearch",
       "elastic:elasticsearch"),
]


def identify_app(title: str, headers: dict[str, str], body: str) -> Fingerprint | None:
    """Recognise the web app from a fetched home page, or None."""
    for header, rule in APP_HEADER_RULES.items():
        if header in headers and (fp := _apply(rule, headers[header])):
            return fp
    for rule in TITLE_RULES:
        if title and (fp := _apply(rule, title)):
            return fp
    for rule in BODY_RULES:
        if fp := _apply(rule, body):
            return fp
    return None


def refine_with_app(svc: Service, app: Fingerprint) -> None:
    """Make the app the service's product, keeping the web server as extra info and CPE."""
    if app.product != svc.product:
        if svc.product:
            svc.extrainfo = "; ".join(x for x in (f"on {svc.label}", svc.extrainfo) if x)
        svc.product, svc.version = app.product, app.version
    elif app.version and not svc.version:
        svc.version = app.version
    else:
        return  # nothing new
    app_cpes = app.cpes or []
    app_keys = {_cpe_key(c) for c in app_cpes}
    svc.cpes = app_cpes + [c for c in svc.cpes if _cpe_key(c) not in app_keys]


def _cpe_key(cpe: str) -> str:
    """'cpe:/a:apache:tomcat:8.5' -> 'apache:tomcat' (same product, any version)."""
    return ":".join(cpe.split(":")[2:4])
