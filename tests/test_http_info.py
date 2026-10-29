import asyncio
import ssl
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dingdongditch import http_info, own_scanner
from dingdongditch.cli import app
from dingdongditch.fingerprints import fingerprint, identify_app, refine_with_app
from dingdongditch.http_info import parse_page
from dingdongditch.nmap_parser import Service

FIXTURES = Path(__file__).parent / "fixtures"


def page(*headers: str, body: str = "") -> bytes:
    head = "HTTP/1.1 200 OK\r\n" + "".join(h + "\r\n" for h in headers)
    return (head + "\r\n" + body).encode()


# --- parse_page -------------------------------------------------------------


def test_title_is_unescaped_and_tidied():
    raw = page("Content-Type: text/html", body="<html><head><TITLE>\n  Dashboard &amp;\n"
               "  more [Jenkins] </TITLE></head>")
    title, _, _ = parse_page(raw)
    assert title == "Dashboard & more [Jenkins]"


def test_only_telling_headers_are_kept():
    raw = page("Server: Apache/2.4.49", "X-Powered-By: PHP/7.4.3", "Content-Length: 10",
               "Set-Cookie: secret=1", 'WWW-Authenticate: Basic realm="Admin"')
    _, headers, _ = parse_page(raw)
    assert headers == {
        "server": "Apache/2.4.49",
        "x-powered-by": "PHP/7.4.3",
        "www-authenticate": 'Basic realm="Admin"',
    }


def test_page_text_is_cleaned_and_capped():
    raw = page(body="<title>\x1b[31mevil" + "A" * 500 + "</title>")
    title, _, _ = parse_page(raw)
    assert title.startswith("\\x1b[31mevil")
    assert len(title) == http_info.TITLE_MAX


def test_no_title():
    assert parse_page(page(body="<html>hi</html>"))[0] == ""


def test_bare_newline_responses():
    title, headers, _ = parse_page(b"HTTP/1.0 200 OK\nServer: x\n\n<title>Hi</title>")
    assert title == "Hi" and headers == {"server": "x"}


# --- recognising the app ------------------------------------------------------


@pytest.mark.parametrize("title, product, version, cpe", [
    ("Apache Tomcat/8.5.19", "Apache Tomcat", "8.5.19", "cpe:/a:apache:tomcat:8.5.19"),
    ("Dashboard [Jenkins]", "Jenkins", "", "cpe:/a:jenkins:jenkins"),
    ("Struts2 Showcase", "Apache Struts", "", "cpe:/a:apache:struts"),
    ("Solr Admin", "Apache Solr", "", "cpe:/a:apache:solr"),
    ("phpMyAdmin", "phpMyAdmin", "", "cpe:/a:phpmyadmin:phpmyadmin"),
    ("Login to Webmin", "Webmin", "", "cpe:/a:webmin:webmin"),
])
def test_app_from_title(title, product, version, cpe):
    fp = identify_app(title, {}, "")
    assert (fp.product, fp.version, fp.cpes) == (product, version, [cpe])


def test_app_from_headers():
    fp = identify_app("", {"x-generator": "Drupal 7 (http://drupal.org)"}, "")
    assert (fp.product, fp.version) == ("Drupal", "7")


def test_elasticsearch_from_json_body():
    body = '{"name":"node-1","version":{"number":"1.4.2","lucene_version":"4.10.2"}}'
    fp = identify_app("", {}, body)
    assert (fp.product, fp.version) == ("Elasticsearch", "1.4.2")


def test_unknown_page():
    assert identify_app("Welcome to my site", {}, "<p>hello</p>") is None


def test_app_replaces_server_but_keeps_its_cpe():
    svc = Service("10.0.0.5", 8080, "tcp", "open", name="http", product="Jetty",
                  version="9.4.41", cpes=["cpe:/a:eclipse:jetty:9.4.41"])
    refine_with_app(svc, identify_app("Dashboard [Jenkins]", {}, ""))
    assert (svc.product, svc.version) == ("Jenkins", "")
    assert svc.extrainfo == "on Jetty 9.4.41"
    assert svc.cpes == ["cpe:/a:jenkins:jenkins", "cpe:/a:eclipse:jetty:9.4.41"]


def test_same_app_gains_a_version_without_duplicate_cpe():
    svc = Service("10.0.0.5", 8080, "tcp", "open", name="http", product="Apache Tomcat",
                  cpes=["cpe:/a:apache:tomcat"])
    refine_with_app(svc, identify_app("Apache Tomcat/8.5.19", {}, ""))
    assert svc.version == "8.5.19"
    assert svc.cpes == ["cpe:/a:apache:tomcat:8.5.19"]


# --- fetching from fake web servers ---------------------------------------


def run_against(reply: bytes, svc_kwargs: dict, tls: bool = False) -> tuple[Service, bytes]:
    """Serve `reply` on localhost, run the http_info step on one service, return it."""
    requests = []

    async def handler(reader, writer):
        requests.append(await reader.read(1024))
        writer.write(reply)
        await writer.drain()
        writer.close()

    async def main():
        ctx = None
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(FIXTURES / "test_only_cert.pem", FIXTURES / "test_only_key.pem")
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        svc = Service("127.0.0.1", port, "tcp", "open", tls=tls, **svc_kwargs)
        async with server:
            await http_info._add_http_info([svc], concurrency=5, timeout=2.0)
        return svc

    svc = asyncio.run(main())
    return svc, requests[0] if requests else b""


TOMCAT = page("Server: Apache-Coyote/1.1", "Content-Type: text/html",
              body="<!DOCTYPE html><html><head><title>Apache Tomcat/8.5.19</title>")


def test_fetches_title_and_finds_tomcat_version():
    svc, request = run_against(
        TOMCAT, {"name": "http", "product": "Apache Tomcat", "cpes": ["cpe:/a:apache:tomcat"]}
    )
    assert request.startswith(b"GET / HTTP/1.0\r\n")
    assert svc.http_title == "Apache Tomcat/8.5.19"
    assert svc.http_headers == {"server": "Apache-Coyote/1.1"}
    assert (svc.product, svc.version) == ("Apache Tomcat", "8.5.19")


def test_fetches_over_tls_for_https():
    svc, _ = run_against(TOMCAT, {"name": "https"}, tls=True)
    assert svc.http_title == "Apache Tomcat/8.5.19"


def test_non_web_services_are_left_alone():
    svc, request = run_against(TOMCAT, {"name": "ssh"})
    assert request == b"" and svc.http_title == ""


def test_non_http_reply_is_ignored():
    svc, _ = run_against(b"SSH-2.0-OpenSSH_7.4\r\n", {"name": "http"})
    assert svc.http_title == "" and svc.http_headers == {}


# --- wiring -------------------------------------------------------------------


def test_only_karen_mode_fetches_pages(monkeypatch):
    calls = []
    monkeypatch.setattr(own_scanner.connect_scan, "scan", lambda *a, **k: [])
    monkeypatch.setattr(own_scanner.probes, "add_banners", lambda s, **k: s)
    monkeypatch.setattr(http_info, "add_http_info", lambda s, **k: calls.append(1) or s)

    own_scanner.run_scan(["127.0.0.1"], [80])
    assert calls == []
    own_scanner.run_scan(["127.0.0.1"], [80], karen_mode=True)
    assert calls == [1]


def test_table_escapes_markup_from_the_target(monkeypatch):
    # Unescaped, rich would swallow these tags and restyle the output.
    evil = Service("10.0.0.5", 80, "tcp", "open", name="http", product="[red]Evil",
                   http_title="[b]x[/b]")
    monkeypatch.setattr(own_scanner, "run_scan", lambda *a, **k: fingerprint([evil]))
    result = CliRunner().invoke(app, ["scan", "10.0.0.5", "-p", "80"])
    assert result.exit_code == 0, result.output
    assert "[red]Evil" in result.stdout
    assert "[b]x[/b]" in result.stdout
