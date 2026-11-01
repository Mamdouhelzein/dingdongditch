import asyncio
import json
import socketserver
import ssl
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dingdongditch import misconfig, own_scanner
from dingdongditch.cli import app
from dingdongditch.misconfig import (
    FTP_ANONYMOUS,
    OPEN_SHELL,
    REDIS_NO_PASSWORD,
    TELNET_OPEN,
)
from dingdongditch.nmap_parser import Service
from dingdongditch.probes import clean_banner

FIXTURES = Path(__file__).parent / "fixtures"
USER = b"USER anonymous"
PASS = b"PASS anonymous@"
QUIT = b"QUIT"


@pytest.fixture(autouse=True)
def short_greeting_wait(monkeypatch):
    monkeypatch.setattr(misconfig.probes, "GREETING_TIMEOUT", 0.2)


def fake_ftp(replies: dict[bytes, bytes], greeting: bytes = b"220 Welcome\r\n"):
    """A fake FTP server: greets, then answers each command from `replies`. Logs commands."""
    commands = []

    async def handler(reader, writer):
        try:
            writer.write(greeting)
            await writer.drain()
            while line := await reader.readline():
                command = line.strip()
                commands.append(command)
                writer.write(replies.get(command, b"502 Not implemented\r\n"))
                await writer.drain()
                if command == QUIT:
                    break
        except OSError:
            pass
        finally:
            writer.close()

    return handler, commands


def run_checks(handler, name="ftp", tls=False, timeout=2.0, state="open") -> Service:
    async def main():
        ctx = None
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(FIXTURES / "test_only_cert.pem", FIXTURES / "test_only_key.pem")
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        svc = Service("127.0.0.1", port, "tcp", state, name=name, tls=tls)
        async with server:
            await misconfig._run_checks([svc], concurrency=5, timeout=timeout)
            server.close()
        return svc

    return asyncio.run(main())


ALLOWED = {USER: b"331 Send password\r\n", PASS: b"230 Login successful\r\n",
           QUIT: b"221 Goodbye\r\n"}


def test_anonymous_ftp_confirmed():
    handler, commands = fake_ftp(ALLOWED)
    assert run_checks(handler).findings == [FTP_ANONYMOUS]
    assert FTP_ANONYMOUS.status == "CONFIRMED"


def test_sends_only_login_and_quit():
    # The safety promise: no other credentials, and no LIST / RETR / STOR.
    handler, commands = fake_ftp(ALLOWED)
    run_checks(handler)
    assert commands == [USER, PASS, QUIT]


def test_rejected_login_is_not_a_finding():
    handler, commands = fake_ftp({USER: b"331 Send password\r\n", PASS: b"530 Login incorrect\r\n"})
    assert run_checks(handler).findings == []
    assert commands == [USER, PASS, QUIT]  # exactly one try, no guessing


def test_anonymous_user_refused_outright():
    handler, commands = fake_ftp({USER: b"530 Anonymous not allowed\r\n"})
    assert run_checks(handler).findings == []
    assert PASS not in commands


def test_login_without_password_step():
    handler, commands = fake_ftp({USER: b"230 Logged in\r\n"})
    assert run_checks(handler).findings == [FTP_ANONYMOUS]
    assert commands == [USER, QUIT]


def test_multi_line_replies():
    replies = {USER: b"331 Send password\r\n",
               PASS: b"230-Welcome\r\n230-Rules apply\r\n230 Logged in\r\n"}
    greeting = b"220-Welcome to the lab\r\n220-Be nice\r\n220 Ready\r\n"
    handler, _ = fake_ftp(replies, greeting)
    assert run_checks(handler).findings == [FTP_ANONYMOUS]


@pytest.mark.parametrize("greeting", [
    b"SSH-2.0-OpenSSH_7.4\r\n",
    b"421 Too many connections\r\n",
    b"hello\r\n",
])
def test_no_login_sent_to_things_that_arent_ready_ftp(greeting):
    handler, commands = fake_ftp(ALLOWED, greeting)
    assert run_checks(handler).findings == []
    assert commands == []


def test_only_ftp_services_are_checked():
    handler, commands = fake_ftp(ALLOWED)
    assert run_checks(handler, name="ssh").findings == []
    assert commands == []


def test_closed_services_are_skipped():
    handler, commands = fake_ftp(ALLOWED)
    assert run_checks(handler, state="closed").findings == []
    assert commands == []


def test_implicit_tls():
    handler, commands = fake_ftp(ALLOWED)
    assert run_checks(handler, name="ftp", tls=True).findings == [FTP_ANONYMOUS]
    assert commands == [USER, PASS, QUIT]


def test_server_that_hangs_gives_no_finding():
    async def hang(reader, writer):
        writer.write(b"220 Welcome\r\n")
        await writer.drain()
        await reader.read(1024)
        await asyncio.sleep(1)
        writer.close()

    assert run_checks(hang, timeout=0.1).findings == []


def test_slow_drip_server_is_cut_off():
    # Keeps a check alive with a new line just inside each timeout; BUDGET ends it.
    async def drip(reader, writer):
        try:
            writer.write(b"220-Welcome\r\n")
            for _ in range(100):
                await asyncio.sleep(0.05)
                writer.write(b"220-more\r\n")
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    assert run_checks(drip, timeout=0.1).findings == []


def test_huge_line_without_newline_gives_no_finding():
    async def flood(reader, writer):
        try:
            writer.write(b"220" + b"A" * 100_000)
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    assert run_checks(flood).findings == []


def test_unreachable_service_gives_no_finding():
    svc = Service("127.0.0.1", 1, "tcp", "open", name="ftp")
    asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=0.05))
    assert svc.findings == []


# --- wiring and output --------------------------------------------------------


def test_only_karen_mode_runs_checks(monkeypatch):
    calls = []
    monkeypatch.setattr(own_scanner.connect_scan, "scan", lambda *a, **k: [])
    monkeypatch.setattr(own_scanner.probes, "add_banners", lambda s, **k: s)
    monkeypatch.setattr(own_scanner.http_info, "add_http_info", lambda s, **k: s)
    monkeypatch.setattr(own_scanner.tls_info, "add_tls_info", lambda s, **k: s)
    monkeypatch.setattr(misconfig, "add_findings", lambda s, **k: calls.append(1) or s)

    own_scanner.run_scan(["127.0.0.1"], [21])
    assert calls == []
    own_scanner.run_scan(["127.0.0.1"], [21], karen_mode=True)
    assert calls == [1]


def _confirmed_service() -> Service:
    return Service("10.0.0.5", 21, "tcp", "open", name="ftp", findings=[FTP_ANONYMOUS])


def test_table_shows_confirmed_with_why_and_fix(monkeypatch):
    monkeypatch.setattr(own_scanner, "run_scan", lambda *a, **k: [_confirmed_service()])
    result = CliRunner().invoke(app, ["scan", "10.0.0.5", "-p", "21"])
    assert result.exit_code == 0, result.output
    assert "model not trained" not in result.stdout
    assert result.stdout.count("CONFIRMED") == 2  # the Risk column and the details
    assert "10.0.0.5:21 Anonymous FTP login allowed" in result.stdout
    assert "Why:" in result.stdout and "anonymous_enable=NO" in result.stdout


def test_json_has_findings(monkeypatch):
    monkeypatch.setattr(own_scanner, "run_scan", lambda *a, **k: [_confirmed_service()])
    result = CliRunner().invoke(app, ["scan", "10.0.0.5", "-p", "21", "--json"])
    finding = json.loads(result.stdout)[0]["findings"][0]
    assert finding["check"] == "ftp-anonymous" and finding["status"] == "CONFIRMED"
    assert finding["why"] and finding["fix"]


def test_full_scan_finds_anonymous_ftp():
    """The real command, from finding the port to CONFIRMED, against a threaded fake server."""
    logins = []

    class Ftp(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.wfile.write(b"220 (vsFTPd 2.3.4)\r\n")
                for line in self.rfile:
                    command = line.strip()
                    if command == USER:
                        self.wfile.write(b"331 Please specify the password.\r\n")
                    elif command == PASS:
                        logins.append(command)
                        self.wfile.write(b"230 Login successful.\r\n")
                    else:
                        self.wfile.write(b"221 Goodbye.\r\n")
                        return
            except OSError:
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Ftp) as server:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        result = CliRunner().invoke(
            app, ["scan", "127.0.0.1", "-p", str(port), "--karen-mode", "--json", "-t", "5"]
        )
        server.shutdown()

    assert result.exit_code == 0, result.output
    [svc] = json.loads(result.stdout)
    assert (svc["name"], svc["product"], svc["version"]) == ("ftp", "vsftpd", "2.3.4")
    assert [f["check"] for f in svc["findings"]] == ["ftp-anonymous"]
    assert logins == [PASS]  # logged in exactly once


# --- Redis with no password ---------------------------------------------------


def redis(banner: bytes, name: str = "redis") -> Service:
    svc = Service("10.0.0.5", 6379, "tcp", "open", name=name, banner=clean_banner(banner))
    asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=0.1))
    return svc


OPEN_REDIS = b"$3197\r\n# Server\r\nredis_version:5.0.7\r\nredis_mode:standalone\r\n"


def test_redis_answering_info_is_confirmed():
    assert redis(OPEN_REDIS).findings == [REDIS_NO_PASSWORD]


@pytest.mark.parametrize("banner", [
    b"-NOAUTH Authentication required.\r\n",
    b"-DENIED Redis is running in protected mode because protected mode is enabled\r\n",
    b"-ERR unknown command `INFO`\r\n",
    b"",
    # The words alone prove nothing: this isn't an answer to INFO.
    b"HTTP/1.1 200 OK\r\n\r\nredis_version:5.0.7\r\n",
    b"redis_version:5.0.7\r\n",
])
def test_redis_without_proof_is_not_a_finding(banner):
    assert redis(banner).findings == []


def test_redis_check_only_runs_on_redis():
    assert redis(OPEN_REDIS, name="http").findings == []


def test_redis_check_sends_nothing():
    # Unreachable address on purpose: the proof must come from the banner alone.
    svc = Service("127.0.0.1", 1, "tcp", "open", name="redis", banner=clean_banner(OPEN_REDIS))
    asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=0.05))
    assert svc.findings == [REDIS_NO_PASSWORD]


def run_fake_redis(reply_to_info: bytes) -> tuple[dict, list[bytes]]:
    """The real command in Karen mode against a threaded fake Redis on an unusual port."""
    received = []

    class Redis(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                for line in self.rfile:
                    received.append(line.strip())
                    if line.startswith(b"INFO server"):
                        self.wfile.write(reply_to_info)
                    elif not line.strip():
                        continue
                    else:
                        self.wfile.write(b"-ERR unknown command\r\n")
            except OSError:
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Redis) as server:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        result = CliRunner().invoke(
            app, ["scan", "127.0.0.1", "-p", str(port), "--karen-mode", "--json", "-t", "5"]
        )
        server.shutdown()
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)[0], received


def test_full_scan_finds_open_redis_on_unusual_port():
    svc, received = run_fake_redis(OPEN_REDIS)
    assert (svc["name"], svc["product"], svc["version"]) == ("redis", "Redis", "5.0.7")
    assert [f["check"] for f in svc["findings"]] == ["redis-no-password"]
    # Karen mode's probes reach it (HTTP, a TLS hello, INFO), but no real data command does.
    assert received.count(b"INFO server") == 1
    for command in (b"AUTH", b"SET", b"GET", b"KEYS", b"SCAN", b"CONFIG", b"FLUSHALL", b"SAVE"):
        assert not [line for line in received if line.upper().startswith(command + b" ")]


def test_full_scan_with_password_set_reports_nothing():
    svc, _ = run_fake_redis(b"-NOAUTH Authentication required.\r\n")
    assert (svc["name"], svc["product"]) == ("redis", "Redis")
    assert svc["findings"] == []


# --- telnet ---------------------------------------------------------------------


def telnet(banner: bytes, name: str = "telnet", tls: bool = False) -> Service:
    # Unreachable address on purpose: the proof must come from the banner alone.
    svc = Service("127.0.0.1", 1, "tcp", "open", name=name, tls=tls,
                  banner=clean_banner(banner))
    asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=0.05))
    return svc


@pytest.mark.parametrize("banner", [
    b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23",   # DO terminal type, ...
    b"\xff\xfb\x01\xff\xfb\x03",               # WILL echo, ...
    b"Ubuntu 18.04 LTS\r\nmetasploitable login: ",
    b"Username: ",
    b"Password:",
])
def test_telnet_confirmed(banner):
    assert telnet(banner).findings == [TELNET_OPEN]


@pytest.mark.parametrize("banner", [
    b"",                       # a silent port 23 could be anything
    b"Welcome to my service\r\n",
    b"please login: now\r\n",  # the words, but it isn't a prompt
])
def test_telnet_without_proof_is_not_a_finding(banner):
    assert telnet(banner).findings == []


def test_telnet_inside_tls_is_not_cleartext():
    assert telnet(b"\xff\xfd\x18", tls=True).findings == []


def test_login_prompt_elsewhere_is_not_telnet():
    assert telnet(b"Username: ", name="http").findings == []


def test_full_scan_finds_telnet_and_sends_it_nothing():
    received = []

    class Telnet(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.wfile.write(b"\xff\xfd\x18\xff\xfd\x20")
                self.connection.settimeout(0.5)
                data = self.connection.recv(1024)
                if data:
                    received.append(data)
            except OSError:
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Telnet) as server:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        result = CliRunner().invoke(
            app, ["scan", "127.0.0.1", "-p", str(port), "--karen-mode", "--json", "-t", "5"]
        )
        server.shutdown()

    assert result.exit_code == 0, result.output
    [svc] = json.loads(result.stdout)
    assert svc["name"] == "telnet"
    assert [f["check"] for f in svc["findings"]] == ["telnet-open"]
    assert received == []  # no login attempt, not even a reply to its negotiation


# --- slow FTP greeting and open shells ------------------------------------------


def test_ftp_check_waits_for_a_slow_greeting(monkeypatch):
    monkeypatch.setattr(misconfig.probes, "GREETING_TIMEOUT", 1.0)
    handler, commands = fake_ftp(ALLOWED)

    async def slow(reader, writer):
        await asyncio.sleep(0.5)  # longer than the timeout below
        await handler(reader, writer)

    assert run_checks(slow, timeout=0.2).findings == [FTP_ANONYMOUS]
    assert commands == [USER, PASS, QUIT]


def shell(banner: bytes, name: str = "bindshell") -> Service:
    # Unreachable address on purpose: the proof must come from the banner alone.
    svc = Service("127.0.0.1", 1, "tcp", "open", name=name, banner=clean_banner(banner))
    asyncio.run(misconfig._run_checks([svc], concurrency=1, timeout=0.05))
    return svc


def test_open_shell_is_confirmed():
    assert shell(b"root@metasploitable:/# ").findings == [OPEN_SHELL]


def test_shell_check_needs_a_real_prompt():
    assert shell(b"hello there").findings == []


def test_full_scan_finds_an_open_shell_and_types_nothing():
    received = []

    class Shell(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                self.wfile.write(b"root@metasploitable:/# ")
                self.connection.settimeout(0.5)
                data = self.connection.recv(1024)
                if data:
                    received.append(data)
            except OSError:
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Shell) as server:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        result = CliRunner().invoke(
            app, ["scan", "127.0.0.1", "-p", str(port), "--karen-mode", "--json", "-t", "5"]
        )
        server.shutdown()

    assert result.exit_code == 0, result.output
    [svc] = json.loads(result.stdout)
    assert svc["name"] == "bindshell"
    assert [f["check"] for f in svc["findings"]] == ["open-shell"]
    assert received == []  # not one keystroke reached the shell
