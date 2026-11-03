import asyncio
import socket
import struct

import pytest
from test_probes import run_with_server

from dingdongditch import conversations, own_scanner
from dingdongditch.conversations import add_versions, irc_hello, smb_hello
from dingdongditch.fingerprints import identify
from dingdongditch.nmap_parser import Service
from dingdongditch.os_guess import clue_from

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


# --- SMB ----------------------------------------------------------------------

UNICODE = 0x8000


def smb_reply(command: int, words: bytes, data: bytes, flags2: int = 0x4001,
              status: int = 0) -> bytes:
    header = (b"\xffSMB" + bytes([command]) + struct.pack("<I", status) + b"\x98"
              + struct.pack("<H", flags2) + b"\0" * 12 + struct.pack("<HHHH", 0, 0xDDD, 100, 1))
    return conversations._netbios(
        header + bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data
    )


def negotiate_reply(flags2=0x4001, capabilities=0, domain="WORKGROUP", status=0):
    challenge = b"8bytes!!"
    words = struct.pack("<HBHHIIIIQhB", 0, 3, 50, 1, 16644, 65536, 0xC0FFEE, capabilities, 0,
                        0, len(challenge))
    encoding = "utf-16-le" if flags2 & UNICODE else "latin-1"
    data = challenge + (domain + "\0").encode(encoding)
    return smb_reply(0x72, words, data, flags2, status)


def session_reply(*names: str, flags2=0x4001):
    data = b""
    if flags2 & UNICODE:
        data = b"\0" + b"".join((n + "\0").encode("utf-16-le") for n in names)  # 1 byte pad
    else:
        data = b"".join((n + "\0").encode("latin-1") for n in names)
    return smb_reply(0x73, struct.pack("<BBHH", 0xFF, 0, 0, 0), data, flags2)


SAMBA = ("Unix", "Samba 3.0.20-Debian", "WORKGROUP")  # Metasploitable 2
WINDOWS = ("Windows 7 Professional 7601 Service Pack 1", "Windows 7 Professional 6.1", "LAB")


def fake_smb(requests: list[bytes], negotiate=None, session=None, netbios=False):
    async def handler(reader, writer):
        async def hear() -> bytes:
            head = await reader.readexactly(4)
            body = await reader.readexactly(int.from_bytes(head[1:], "big"))
            requests.append(head + body)
            return head

        try:
            if netbios:
                await hear()
                writer.write(b"\x82\0\0\0")
            negotiate_ = negotiate_reply() if negotiate is None else negotiate
            for reply in (negotiate_, session or session_reply(*SAMBA)):
                await hear()
                if not reply:  # an SMB1-less server just hangs up
                    writer.close()
                    return
                writer.write(reply)
                await writer.drain()
            await reader.read()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        writer.close()

    return handler


def smb_talk(handler, monkeypatch=None, netbios=False):
    async def client(port):
        if netbios:
            monkeypatch.setattr(conversations, "NETBIOS_SESSION_PORTS", {port})
        return await smb_hello("127.0.0.1", port, False, 2.0)

    return run_with_server(handler, client)


def test_smb_names_from_samba():
    requests: list[bytes] = []
    text = smb_talk(fake_smb(requests))
    assert text == (
        "smb native os: Unix\nsmb lan manager: Samba 3.0.20-Debian\nsmb domain: WORKGROUP"
    )
    assert requests[0] == conversations.SMB_NEGOTIATE


def test_smb_session_is_anonymous():
    requests: list[bytes] = []
    smb_talk(fake_smb(requests))
    setup = requests[1][4:]
    assert setup[4] == 0x73 and setup[32] == 13  # session setup, 13 words
    words = setup[33:59]
    session_key, oem_len, unicode_len = struct.unpack_from("<IHH", words, 10)
    assert session_key == 0xC0FFEE  # echoed from the negotiate reply
    assert (oem_len, unicode_len) == (0, 0)  # no passwords
    assert setup[59:] == b"\x04\x00\0\0\0\0"  # 4 bytes of data: empty user and names


def test_smb_names_in_unicode_from_windows():
    text = smb_talk(fake_smb([], negotiate_reply(0x4001 | UNICODE, domain="LAB"),
                             session_reply(*WINDOWS, flags2=0x4001 | UNICODE)))
    assert text.splitlines() == [
        "smb native os: Windows 7 Professional 7601 Service Pack 1",
        "smb lan manager: Windows 7 Professional 6.1",
        "smb domain: LAB",
    ]


def test_smb_on_netbios_port_sends_session_request_first(monkeypatch):
    requests: list[bytes] = []
    text = smb_talk(fake_smb(requests, netbios=True), monkeypatch, netbios=True)
    assert requests[0] == conversations.SMB_SESSION_REQUEST
    assert requests[0][:1] == b"\x81"
    assert "Samba 3.0.20" in text


def test_smb_domain_from_negotiate_when_session_gives_none():
    text = smb_talk(fake_smb([], session=session_reply("Unix", "Samba 4.9.5-Debian")))
    assert text.splitlines()[-1] == "smb domain: WORKGROUP"


def test_smb_server_refusing_smb1():
    refused = negotiate_reply(status=0xC00000BB)  # STATUS_NOT_SUPPORTED
    assert smb_talk(fake_smb([], refused)) == ""
    with pytest.raises(EOFError):  # most just hang up; add_versions treats that as no answer
        smb_talk(fake_smb([], negotiate=b""))


def test_smb_names_are_cleaned():
    text = smb_talk(fake_smb([], session=session_reply("Unix\x1b[31m", "Samba\n3.0.20", "")))
    native_os, lan_manager = text.splitlines()[:2]
    assert native_os == r"smb native os: Unix\x1b[31m"  # escape code shown, not run
    assert lan_manager == "smb lan manager: Samba 3.0.20"  # one line, can't fake another


@pytest.mark.parametrize("names, product, version, extra, cpe", [
    (SAMBA, "Samba smbd", "3.0.20", "Debian", "cpe:/a:samba:samba:3.0.20"),
    (("Windows 6.1", "Samba 4.13.17-Ubuntu", "LAB"), "Samba smbd", "4.13.17", "Ubuntu",
     "cpe:/a:samba:samba:4.13.17"),
    (WINDOWS, "Microsoft Windows SMB", "", WINDOWS[0], ""),
    (("Unix", "", "LAB"), "", "", "", ""),
])
def test_smb_fingerprints(names, product, version, extra, cpe):
    banner = "\n".join(f"smb {label}: {value}" for label, value in
                       zip(("native os", "lan manager", "domain"), names, strict=True) if value)
    fp = identify(banner)
    assert (fp.name, fp.product, fp.version, fp.extrainfo) == ("smb", product, version, extra)
    assert fp.cpes == ([cpe] if cpe else [])


def test_smb_windows_is_an_os_clue():
    windows = svc(445, "smb", banner=f"smb native os: {WINDOWS[0]}")
    assert clue_from(windows).distro == "Windows"
    samba = svc(445, "smb", banner="smb lan manager: Samba 3.0.20-Debian")
    assert clue_from(samba).distro == "Debian"


# --- servers that say "too fast" ----------------------------------------------


def throttled_irc(how: str):
    async def handler(reader, writer):
        await reader.readline()
        if how == "error":
            writer.write(b"ERROR :Closing Link: [127.0.0.1] (Throttled: Reconnecting too fast)"
                         b" -Email admin@lab for more information.\r\n")
        elif how == "reset":  # slam the door (a TCP reset on Linux; Windows still says goodbye)
            sock = writer.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.close()  # "silent": just hang up

    return handler


@pytest.mark.parametrize("how", ["error", "reset", "silent"])
def test_irc_throttled_means_try_later(how):
    with pytest.raises(conversations.TryLater):
        talk_to(throttled_irc(how))


def test_irc_other_errors_just_end_the_conversation():
    async def handler(reader, writer):
        await reader.readline()
        writer.write(b"ERROR :Closing Link: [127.0.0.1] (You are banned)\r\n")
        writer.close()

    assert talk_to(handler) == ""


def test_add_versions_waits_and_tries_once_more(monkeypatch):
    attempts = []

    async def throttled_once(host, port, use_tls, timeout):
        attempts.append(port)
        if len(attempts) == 1:
            raise conversations.TryLater("too fast")
        return ":irc.lab 002 ddd1 :Your host is irc.lab, running version Unreal3.2.8.1"

    monkeypatch.setattr(conversations, "RETRY_WAIT", 0)
    monkeypatch.setattr(conversations, "CONVERSATIONS", {"irc": throttled_once})
    (irc,) = add_versions([svc(6667, "irc")])
    assert attempts == [6667, 6667]
    assert irc.version == "3.2.8.1"


def test_add_versions_gives_up_after_the_second_refusal(monkeypatch):
    async def always_throttled(host, port, use_tls, timeout):
        raise conversations.TryLater("too fast")

    monkeypatch.setattr(conversations, "RETRY_WAIT", 0)
    monkeypatch.setattr(conversations, "CONVERSATIONS", {"irc": always_throttled})
    (irc,) = add_versions([svc(6667, "irc")])
    assert irc.version == ""


def test_add_versions_takes_turns_on_one_host(monkeypatch):
    running, most = 0, 0

    async def slow(host, port, use_tls, timeout):
        nonlocal running, most
        running += 1
        most = max(most, running)
        await asyncio.sleep(0.05)
        running -= 1
        return ""

    monkeypatch.setattr(conversations, "CONVERSATIONS", {"irc": slow})
    add_versions([svc(6667, "irc"), svc(6697, "irc")])
    assert most == 1
