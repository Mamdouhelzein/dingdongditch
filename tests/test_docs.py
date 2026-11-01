"""The README and man page must keep matching what the tool really does."""

import re
import shlex
from pathlib import Path

import pytest
import typer.main

from dingdongditch import __version__, misconfig
from dingdongditch.cli import app
from dingdongditch.nmap_parser import Finding, Service
from dingdongditch.ports import PROFILES

ROOT = Path(__file__).parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
RAW_MAN = (ROOT / "man" / "dingdongditch.1").read_text(encoding="utf-8")
MAN = re.sub(r"\\f[BIRP]", "", RAW_MAN).replace("\\-", "-")

CLICK_APP = typer.main.get_command(app)
COMMANDS = CLICK_APP.commands
OPTIONS = {
    flag
    for command in [CLICK_APP, *COMMANDS.values()]
    for param in command.params
    for flag in param.opts
    if flag.startswith("-")
} | {"--help"}
FINDINGS = [v for v in vars(misconfig).values() if isinstance(v, Finding)]


@pytest.mark.parametrize("command", COMMANDS)
def test_man_page_has_every_command(command):
    assert re.search(rf"^\.B {command}$", MAN, re.MULTILINE)


@pytest.mark.parametrize("option", sorted(OPTIONS))
def test_man_page_has_every_option(option):
    assert re.search(rf"(?<![\w-]){option}(?![\w-])", MAN)


@pytest.mark.parametrize("option", sorted(OPTIONS - {"--help", "-V", "--version"}))
def test_readme_has_every_option(option):
    assert re.search(rf"(?<![\w-]){option}(?![\w-])", README)


@pytest.mark.parametrize("line", [
    *re.findall(r"^dingdongditch ((?:scan|analyze) .+?)(?:\s+#.*)?$", README, re.MULTILINE),
    *re.findall(r"^\.B dingdongditch ((?:scan|analyze) .+)$", MAN, re.MULTILINE),
])
def test_examples_are_valid_commands(line):
    command, *args = shlex.split(line)
    COMMANDS[command].make_context(command, args)  # raises if the options are wrong


def test_man_page_has_no_stale_options():
    allowed = OPTIONS | {"-sV", "-oX"}  # the last two are nmap's
    used = re.findall(r"(?<![\w-])--?[a-zA-Z][\w-]*", MAN)
    assert set(used) - allowed == set()


@pytest.mark.parametrize("finding", FINDINGS, ids=lambda f: f.check)
def test_docs_have_every_check(finding):
    assert finding.check in MAN
    assert finding.check in README


def test_man_page_version_matches():
    assert f'"DingDongDitch {__version__}"' in RAW_MAN


@pytest.mark.parametrize("field", Service.__dataclass_fields__)
def test_man_page_has_every_json_field(field):
    assert re.search(rf"^\.BR? {field}\b", MAN, re.MULTILINE)


def test_man_page_port_counts_match():
    assert f"{len(PROFILES['quick'])} hand-picked" in MAN
    assert f"{len(PROFILES['default']):,} ports in all" in MAN
