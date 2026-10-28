import pytest

from dingdongditch.ports import (
    MOSTLY_UDP,
    PROFILES,
    SERVICE_NAMES,
    TLS_PORTS,
    TOP_PORTS,
    parse_ports,
)


def test_parse_single_ports_and_ranges():
    assert parse_ports("80,22,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_dedupes_and_ignores_spaces():
    assert parse_ports(" 22, 22 ,21-23,") == [21, 22, 23]


def test_parse_reversed_range():
    assert parse_ports("25-20") == [20, 21, 22, 23, 24, 25]


@pytest.mark.parametrize("bad", ["", ",", "0", "65536", "80-70000", "ssh", "1-a"])
def test_parse_rejects_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_profiles_are_sorted_and_nested():
    quick, default, full = (set(PROFILES[p]) for p in ("quick", "default", "full"))
    assert quick <= default <= full
    assert len(PROFILES["full"]) == 65535
    for ports in PROFILES.values():
        assert ports == sorted(ports)


def test_known_ports_have_names():
    assert TOP_PORTS == sorted(SERVICE_NAMES)
    assert TLS_PORTS <= set(SERVICE_NAMES)
    assert MOSTLY_UDP <= set(SERVICE_NAMES)
    assert SERVICE_NAMES[22] == "ssh"
    assert SERVICE_NAMES[6379] == "redis"
