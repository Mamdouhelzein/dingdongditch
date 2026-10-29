"""Turn a banner into service name, product, version and CPE.

e.g. "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7" -> ssh / OpenSSH / 7.4p1 /
cpe:/a:openbsd:openssh:7.4p1. CPE vendor:product names follow NVD so the
CVE matcher can look them up directly.

Banners come from probes.clean_banner, so non-printable bytes appear as
literal "\\xNN" text, which some patterns below rely on.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

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
    _r(r"\\x00\n(?P<version>\d+\.\d+\.\d+)", "mysql", "MySQL", "oracle:mysql"),
    _r(r"is not allowed to connect to this M(?:ySQL|ariaDB) server", "mysql", "MySQL"),
    _r(r"^redis_version:" + _V, "redis", "Redis", "redis:redis"),
    _r(r"^-(?:NOAUTH|DENIED|ERR operation not permitted)", "redis", "Redis"),
    # Message brokers. ActiveMQ OpenWire sends its WireFormatInfo first.
    _r(r"ActiveMQ[\s\S]*?ProviderVersion" + _ESC + _V, "activemq", "Apache ActiveMQ",
       "apache:activemq"),
    _r(r"\\x01ActiveMQ", "activemq", "Apache ActiveMQ", "apache:activemq"),
    _r(r"^AMQP", "amqp"),
    # Remote access
    _r(r"^RFB (?P<extra>\d{3}\.\d{3})", "vnc"),
    _r(r"^\\xff\\xf[b-e]", "telnet"),  # telnet option negotiation (IAC WILL/WONT/DO/DONT)
    # HTTP/2-only servers (often gRPC) open with a SETTINGS frame:
    # 3-byte length, type 0x04, flags 0, stream 0.
    _r(r"^\\x00(?:\\x[0-9a-f]{2}|.){2}\\x04\\x00\\x00\\x00\\x00\\x00", "http2"),
    # Other
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


def identify(banner: str) -> Fingerprint | None:
    """Work out what a service is from its banner, or None if we can't tell."""
    if not banner:
        return None
    if re.match(r"HTTP/\d(?:\.\d)? \d{3}", banner):
        return _identify_http(banner)
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
