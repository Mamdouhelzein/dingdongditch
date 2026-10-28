import socket

import pytest

from dingdongditch import targets
from dingdongditch.targets import parse_targets


def test_single_ip():
    assert parse_targets("172.17.0.2") == ["172.17.0.2"]


def test_commas_and_spaces_both_work():
    assert parse_targets("10.0.0.1,10.0.0.2 10.0.0.3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert parse_targets(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]


def test_subnet_skips_network_and_broadcast():
    ips = parse_targets("192.168.56.0/24")
    assert len(ips) == 254
    assert ips[0] == "192.168.56.1" and ips[-1] == "192.168.56.254"


def test_host_bits_in_subnet_are_ok():
    # 192.168.56.77/30 means the 192.168.56.76/30 network.
    assert parse_targets("192.168.56.77/30") == ["192.168.56.77", "192.168.56.78"]


@pytest.mark.parametrize("spec, expected", [
    ("10.0.0.5/32", ["10.0.0.5"]),
    ("10.0.0.4/31", ["10.0.0.4", "10.0.0.5"]),
])
def test_tiny_subnets_keep_all_addresses(spec, expected):
    assert parse_targets(spec) == expected


def test_duplicates_removed_in_order():
    assert parse_targets("10.0.0.2, 10.0.0.0/30, 10.0.0.2") == ["10.0.0.2", "10.0.0.1"]


def test_ipv6():
    assert parse_targets("::1") == ["::1"]


def test_hostname_is_resolved(monkeypatch):
    def fake_getaddrinfo(host, port, type=0):
        assert host == "lab.local"
        return [
            (socket.AF_INET6, type, 6, "", ("fe80::1", 0, 0, 0)),
            (socket.AF_INET, type, 6, "", ("172.17.0.9", 0)),
        ]

    monkeypatch.setattr(targets.socket, "getaddrinfo", fake_getaddrinfo)
    assert parse_targets("lab.local") == ["172.17.0.9"]


def test_unknown_hostname(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("nope")

    monkeypatch.setattr(targets.socket, "getaddrinfo", fail)
    with pytest.raises(ValueError, match="resolve"):
        parse_targets("does-not-exist.invalid")


def test_subnet_size_limit():
    assert len(parse_targets("10.0.0.0/16")) == 65534
    with pytest.raises(ValueError, match="limit"):
        parse_targets("10.0.0.0/15")
    with pytest.raises(ValueError):
        parse_targets("10.0.0.0/24", max_hosts=100)


@pytest.mark.parametrize("bad", ["", " , ", "-iL", "--script=evil", "10.0.0.0/33"])
def test_rejects_invalid(bad):
    with pytest.raises(ValueError):
        parse_targets(bad)
