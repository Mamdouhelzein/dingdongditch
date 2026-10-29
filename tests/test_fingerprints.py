import pytest

from dingdongditch.fingerprints import fingerprint, identify
from dingdongditch.nmap_parser import Service
from dingdongditch.probes import clean_banner

# Raw bytes as services send them; each goes through clean_banner like in a real scan.
# (raw, name, product, version, cpe)
CASES = [
    # SSH
    (b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
     "ssh", "OpenSSH", "7.4p1", "cpe:/a:openbsd:openssh:7.4p1"),
    (b"SSH-2.0-dropbear_2019.78\r\n",
     "ssh", "Dropbear sshd", "2019.78", "cpe:/a:dropbear_ssh_project:dropbear_ssh:2019.78"),
    (b"SSH-2.0-Cisco-1.25\r\n", "ssh", "", "", ""),
    # FTP
    (b"220 (vsFTPd 2.3.4)\r\n", "ftp", "vsftpd", "2.3.4", "cpe:/a:vsftpd_project:vsftpd:2.3.4"),
    (b"220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [172.17.0.2]\r\n",
     "ftp", "ProFTPD", "1.3.5", "cpe:/a:proftpd:proftpd:1.3.5"),
    (b"220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n",
     "ftp", "Pure-FTPd", "", "cpe:/a:pureftpd:pure-ftpd"),
    (b"220-FileZilla Server 0.9.60 beta\r\n", "ftp", "FileZilla ftpd", "0.9.60",
     "cpe:/a:filezilla-project:filezilla_server:0.9.60"),
    (b"220 Microsoft FTP Service\r\n", "ftp", "", "", ""),
    # Mail
    (b"220 mail.lab ESMTP Postfix (Debian/GNU)\r\n",
     "smtp", "Postfix smtpd", "", "cpe:/a:postfix:postfix"),
    (b"220 mx.lab ESMTP Exim 4.92 Tue, 28 Oct 2026 10:00:00 +0000\r\n",
     "smtp", "Exim smtpd", "4.92", "cpe:/a:exim:exim:4.92"),
    (b"* OK [CAPABILITY IMAP4rev1 LITERAL+] Dovecot ready.\r\n",
     "imap", "Dovecot imapd", "", "cpe:/a:dovecot:dovecot"),
    (b"+OK Dovecot ready.\r\n", "pop3", "Dovecot pop3d", "", "cpe:/a:dovecot:dovecot"),
    # Databases
    (b"J\x00\x00\x00\x0a5.7.33\x00\x08\x00\x00\x00;X,q\x00\xff\xf7",
     "mysql", "MySQL", "5.7.33", "cpe:/a:oracle:mysql:5.7.33"),
    (b"Y\x00\x00\x00\x0a5.5.5-10.3.27-MariaDB-0+deb10u1\x00\x0b\x00\x00\x00",
     "mysql", "MariaDB", "10.3.27", "cpe:/a:mariadb:mariadb:10.3.27"),
    (b"$3197\r\n# Server\r\nredis_version:5.0.7\r\nredis_git_sha1:00000000\r\n",
     "redis", "Redis", "5.0.7", "cpe:/a:redis:redis:5.0.7"),
    (b"-NOAUTH Authentication required.\r\n", "redis", "Redis", "", ""),
    # ActiveMQ OpenWire greeting (shortened)
    (b"\x00\x00\x01\x1e\x01ActiveMQ\x00\x00\x00\x0c\x01\x00\x00\x01\x0c"
     b"\x00\x0cProviderName\x09\x00\x08ActiveMQ"
     b"\x00\x0fProviderVersion\x09\x00\x075.15.15\x00\x11StackTraceEnabled",
     "activemq", "Apache ActiveMQ", "5.15.15", "cpe:/a:apache:activemq:5.15.15"),
    # Other
    (b"RFB 003.008\n", "vnc", "", "", ""),
    (b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23", "telnet", "", "", ""),
    (b"AMQP\x00\x00\x09\x01", "amqp", "", "", ""),
    (b"220 VMware Authentication Daemon Version 1.10: SSL Required\r\n",
     "vmware-auth", "VMware Authentication Daemon", "1.10", ""),
]


@pytest.mark.parametrize("raw, name, product, version, cpe", CASES)
def test_identify(raw, name, product, version, cpe):
    fp = identify(clean_banner(raw))
    assert (fp.name, fp.product, fp.version) == (name, product, version)
    assert fp.cpes == ([cpe] if cpe else [])


def http(*headers: str) -> str:
    return clean_banner(("HTTP/1.1 200 OK\r\n" + "".join(h + "\r\n" for h in headers)).encode())


@pytest.mark.parametrize("server, product, version, cpe", [
    ("Apache/2.4.49 (Unix)", "Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49"),
    ("Apache", "Apache httpd", "", "cpe:/a:apache:http_server"),
    ("Apache-Coyote/1.1", "Apache Tomcat", "", "cpe:/a:apache:tomcat"),
    ("nginx/1.18.0", "nginx", "1.18.0", "cpe:/a:nginx:nginx:1.18.0"),
    ("nginx", "nginx", "", "cpe:/a:nginx:nginx"),
    ("Microsoft-IIS/10.0", "Microsoft IIS httpd", "10.0",
     "cpe:/a:microsoft:internet_information_services:10.0"),
    ("Jetty(9.4.41.v20210516)", "Jetty", "9.4.41.v20210516",
     "cpe:/a:eclipse:jetty:9.4.41.v20210516"),
    ("Werkzeug/0.14.1 Python/3.6.5", "Werkzeug httpd", "0.14.1",
     "cpe:/a:palletsprojects:werkzeug:0.14.1"),
    ("MiniServ/1.910", "Webmin httpd", "1.910", "cpe:/a:webmin:webmin:1.910"),
    ("CouchDB/2.1.0 (Erlang OTP/17)", "CouchDB httpd", "2.1.0", "cpe:/a:apache:couchdb:2.1.0"),
    ("Kestrel", "Kestrel", "", ""),
    ("SomeServer/3.2", "SomeServer", "3.2", ""),
])
def test_http_server_header(server, product, version, cpe):
    fp = identify(http(f"Server: {server}"))
    assert (fp.name, fp.product, fp.version) == ("http", product, version)
    assert fp.cpes == ([cpe] if cpe else [])


def test_http_extra_info():
    fp = identify(http("Server: Apache/2.4.49 (Unix)", "X-Powered-By: PHP/7.4.3"))
    assert fp.extrainfo == "Unix; PHP/7.4.3"


def test_jenkins_header_beats_jetty():
    fp = identify(http("Server: Jetty(9.4.z-SNAPSHOT)", "X-Jenkins: 2.138"))
    assert (fp.product, fp.version) == ("Jenkins", "2.138")
    assert fp.cpes == ["cpe:/a:jenkins:jenkins:2.138"]


def test_docker_api():
    fp = identify(http("Server: Docker/19.03.12 (linux)"))
    assert (fp.name, fp.product, fp.version) == ("docker", "Docker", "19.03.12")


def test_http_without_server_header():
    fp = identify(http("Content-Type: text/html"))
    assert (fp.name, fp.product, fp.cpes) == ("http", "", [])


@pytest.mark.parametrize("banner", ["", "hello there", clean_banner(b"\x00\x01\x02")])
def test_unknown_banners(banner):
    assert identify(banner) is None


def test_fingerprint_fills_services():
    ssh = Service("10.0.0.5", 22, "tcp", "open", name="ssh",
                  banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    web = Service("10.0.0.5", 8443, "tcp", "open", name="https-alt", tls=True,
                  banner=http("Server: nginx/1.18.0"))
    odd = Service("10.0.0.5", 5432, "tcp", "open", name="postgresql", banner="")

    ssh, web, odd = fingerprint([ssh, web, odd])
    assert (ssh.product, ssh.version, ssh.extrainfo) == ("OpenSSH", "8.2p1", "Ubuntu-4ubuntu0.5")
    assert ssh.cpes == ["cpe:/a:openbsd:openssh:8.2p1"]
    assert (web.name, web.label) == ("https", "nginx 1.18.0")
    assert (odd.name, odd.product, odd.cpes) == ("postgresql", "", [])
