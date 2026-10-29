"""A small fake lab on localhost: several services at once, scanned end to end.

Each fake service only behaves like the real one for the first exchange
(greeting or answer to our probe), which is all the scanner looks at.
"""

import socket
import threading

import pytest

from dingdongditch import own_scanner, probes

# name -> (greeting sent on connect, reply to whatever we send first)
FAKES = {
    "ssh": (b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n", None),
    "ftp": (b"220 (vsFTPd 2.3.4)\r\n", None),
    "http": (None, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n"),
    "redis": (None, b"$40\r\n# Server\r\nredis_version:5.0.7\r\n"),
}


def _serve(srv: socket.socket, greeting: bytes | None, reply: bytes | None, stop):
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        with conn:
            conn.settimeout(3)
            try:
                if greeting:
                    conn.sendall(greeting)
                if reply and conn.recv(1024):
                    conn.sendall(reply)
            except OSError:
                pass


@pytest.fixture
def fake_lab(monkeypatch):
    """Start the fake services; return {port: name}."""
    stop = threading.Event()
    sockets, threads, lab = [], [], {}
    for name, (greeting, reply) in FAKES.items():
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(20)
        srv.settimeout(0.2)
        port = srv.getsockname()[1]
        lab[port] = name
        t = threading.Thread(target=_serve, args=(srv, greeting, reply, stop), daemon=True)
        t.start()
        sockets.append(srv)
        threads.append(t)
    # Random ports have no default name, so tell the probes which is Redis
    # (it only answers INFO server) and treat the rest as unknown.
    monkeypatch.setattr(
        probes, "SERVICE_NAMES", {p: n for p, n in lab.items() if n == "redis"}
    )
    yield lab
    stop.set()
    for t in threads:
        t.join()
    for s in sockets:
        s.close()


def test_scan_fake_lab(fake_lab):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    ports = sorted([*fake_lab, closed_port])
    services = own_scanner.run_scan(["127.0.0.1"], ports, timeout=5.0)
    found = {s.port: (s.name, s.product, s.version, s.cpes) for s in services}

    by_name = {name: port for port, name in fake_lab.items()}
    assert found == {
        by_name["ssh"]: ("ssh", "OpenSSH", "7.4p1", ["cpe:/a:openbsd:openssh:7.4p1"]),
        by_name["ftp"]: ("ftp", "vsftpd", "2.3.4", ["cpe:/a:vsftpd_project:vsftpd:2.3.4"]),
        by_name["http"]: ("http", "Apache httpd", "2.4.49",
                          ["cpe:/a:apache:http_server:2.4.49"]),
        by_name["redis"]: ("redis", "Redis", "5.0.7", ["cpe:/a:redis:redis:5.0.7"]),
    }
