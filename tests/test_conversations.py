
import pytest
from test_probes import run_with_server

from dingdongditch import conversations, own_scanner
from dingdongditch.conversations import add_versions, irc_hello
from dingdongditch.fingerprints import identify
from dingdongditch.nmap_parser import Service

# --- IRC --------------------------------------------------------------------

WELCOME = [
    ":irc.lab 001 {nick} :Welcome to the TestNet IRC Network {nick}!dingdongditch@10.0.0.9",
    ":irc.lab 002 {nick} :Your host is irc.lab, running version Unreal3.2.8.1",
    ":irc.lab 003 {nick} :This server was created Mon May 12 2014",
    ":irc.lab 004 {nick} irc.lab Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikr",
    ":irc.lab 005 {nick} WATCH=128 SAFELIST :are supported by this server",
]


def fake_irc(seen: list[str], nick_taken: bool = False, register: bool = True):
    """An IRC server like Metasploitable's UnrealIRCd: it PINGs before welcoming."""

    async def handler(reader, writer):
        async def say(line: str) -> None:
            writer.write(line.encode() + b"\r\n")
            await writer.drain()

        async def hear() -> str:
            line = (await reader.readline()).decode().strip()
            seen.append(line)
            return line

        await say(":irc.lab NOTICE AUTH :*** Looking up your hostname...")
        nick = (await hear()).split()[1]
        await hear()  # USER
        if nick_taken:
            await say(f":irc.lab 433 * {nick} :Nickname is already in use.")
            nick = (await hear()).split()[1]
        if not register:
            await reader.read()  # say nothing more until the client hangs up
            writer.close()
            return
        await say("PING :8D5E1A2C")
        await hear()  # PONG
        for line in WELCOME:
            await say(line.format(nick=nick))
        while line := await hear():
            if line.startswith("QUIT"):
                break
        writer.close()

    return handler


def talk_to(handler):
    return run_with_server(handler, lambda port: irc_hello("127.0.0.1", port, False, 2.0))


def test_irc_registers_and_keeps_the_version_lines():
    seen: list[str] = []
    text = talk_to(fake_irc(seen))
    lines = text.splitlines()
    assert [line.split()[1] for line in lines] == ["002", "004"]
    assert "running version Unreal3.2.8.1" in lines[0]


def test_irc_says_only_what_a_normal_client_says():
    seen: list[str] = []
    talk_to(fake_irc(seen))
    nick, user, pong, quit_ = seen
    assert nick.startswith("NICK ddd")
    assert user == "USER dingdongditch 0 * :dingdongditch"
    assert pong == "PONG :8D5E1A2C"
    assert quit_ == "QUIT :bye"  # no JOIN, no messages, nothing else


def test_irc_picks_another_nick_if_taken():
    seen: list[str] = []
    text = talk_to(fake_irc(seen, nick_taken=True))
    assert seen[0] != seen[2] and seen[2].startswith("NICK ddd")
    assert "Unreal3.2.8.1" in text


def test_irc_gives_up_on_a_server_that_never_welcomes(monkeypatch):
    monkeypatch.setattr(conversations, "IRC_TIME_LIMIT", 0.3)
    assert talk_to(fake_irc([], register=False)) == ""


@pytest.mark.parametrize("version_text, product, version, extra, cpe", [
    ("Unreal3.2.8.1", "UnrealIRCd", "3.2.8.1", "", "cpe:/a:unrealircd:unrealircd:3.2.8.1"),
    ("UnrealIRCd-6.1.0", "UnrealIRCd", "6.1.0", "", "cpe:/a:unrealircd:unrealircd:6.1.0"),
    ("InspIRCd-3", "InspIRCd", "3", "", "cpe:/a:inspircd:inspircd:3"),
    ("ngircd-26.1 (x86_64/pc/linux-gnu)", "ngIRCd", "26.1", "", "cpe:/a:barton:ngircd:26.1"),
    ("hybrid-8.2.24", "ircd-hybrid", "8.2.24", "", ""),
    ("ircd-ratbox-3.0.10", "ircd-ratbox", "3.0.10", "", ""),
    ("solanum-1.0-dev", "", "", "solanum-1.0-dev", ""),
])
def test_irc_fingerprints(version_text, product, version, extra, cpe):
    banner = (
        ":irc.lab NOTICE AUTH :*** Looking up your hostname...\n"
        f":irc.lab 002 ddd12345 :Your host is irc.lab, running version {version_text}"
    )
    fp = identify(banner)
    assert (fp.name, fp.product, fp.version, fp.extrainfo) == ("irc", product, version, extra)
    assert fp.cpes == ([cpe] if cpe else [])


# --- add_versions -------------------------------------------------------------


def svc(port, name, version="", banner="") -> Service:
    return Service("10.0.0.5", port, "tcp", "open", name=name, version=version, banner=banner)


def test_add_versions_talks_only_to_services_without_a_version(monkeypatch):
    asked = []

    async def fake_talk(host, port, use_tls, timeout):
        asked.append(port)
        return ":irc.lab 002 ddd1 :Your host is irc.lab, running version Unreal3.2.8.1"

    monkeypatch.setattr(conversations, "CONVERSATIONS", {"irc": fake_talk})
    notice = ":irc.lab NOTICE AUTH :*** Looking up your hostname..."
    services = add_versions([
        svc(6667, "irc", banner=notice),
        svc(6668, "irc", version="1.0"),  # already known
        svc(22, "ssh"),
    ])
    assert asked == [6667]
    irc = services[0]
    assert (irc.product, irc.version) == ("UnrealIRCd", "3.2.8.1")
    assert irc.banner.startswith(notice)  # what it said first is kept


def test_add_versions_survives_a_failed_conversation(monkeypatch):
    async def broken(host, port, use_tls, timeout):
        raise ConnectionResetError

    monkeypatch.setattr(conversations, "CONVERSATIONS", {"irc": broken})
    (irc,) = add_versions([svc(6667, "irc")])
    assert (irc.name, irc.version) == ("irc", "")


def test_only_karen_mode_has_conversations(monkeypatch):
    calls = []
    monkeypatch.setattr(own_scanner.connect_scan, "scan", lambda *a, **k: [svc(6667, "irc")])
    monkeypatch.setattr(own_scanner.probes, "add_banners", lambda s, **k: s)
    for module, name in [(own_scanner.http_info, "add_http_info"),
                         (own_scanner.tls_info, "add_tls_info"),
                         (own_scanner.misconfig, "add_findings")]:
        monkeypatch.setattr(module, name, lambda s, **k: s)
    monkeypatch.setattr(conversations, "add_versions", lambda s, **k: calls.append(1) or s)
    own_scanner.run_scan(["10.0.0.5"], [6667])
    assert calls == []
    own_scanner.run_scan(["10.0.0.5"], [6667], karen_mode=True)
    assert calls == [1]
