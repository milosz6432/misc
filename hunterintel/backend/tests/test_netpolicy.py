from __future__ import annotations

import ipaddress

import pytest

from hunterintel.core.netpolicy import (
    IPScope,
    classify_ip,
    hostname_scope,
    is_public_ip,
    parse_ip,
    parse_ipv4_loose,
)


@pytest.mark.parametrize(
    ("ip", "scope"),
    [
        ("8.8.8.8", IPScope.PUBLIC),
        ("1.1.1.1", IPScope.PUBLIC),
        ("2606:4700:4700::1111", IPScope.PUBLIC),
        ("10.1.2.3", IPScope.PRIVATE),
        ("172.16.5.5", IPScope.PRIVATE),
        ("172.32.0.1", IPScope.PUBLIC),  # just outside 172.16/12
        ("192.168.1.1", IPScope.PRIVATE),
        ("127.0.0.1", IPScope.LOOPBACK),
        ("127.255.255.254", IPScope.LOOPBACK),
        ("169.254.169.254", IPScope.LINK_LOCAL),  # cloud metadata endpoint
        ("100.64.0.1", IPScope.CGNAT),
        ("0.0.0.0", IPScope.UNSPECIFIED),
        ("224.0.0.1", IPScope.MULTICAST),
        ("255.255.255.255", IPScope.RESERVED),
        ("192.0.2.10", IPScope.DOCUMENTATION),
        ("198.51.100.7", IPScope.DOCUMENTATION),
        ("203.0.113.9", IPScope.DOCUMENTATION),
        ("198.18.0.1", IPScope.RESERVED),
        ("::1", IPScope.LOOPBACK),
        ("::", IPScope.UNSPECIFIED),
        ("fe80::1", IPScope.LINK_LOCAL),
        ("fd00::1", IPScope.PRIVATE),
        ("ff02::1", IPScope.MULTICAST),
        ("2001:db8::1", IPScope.DOCUMENTATION),
        ("::ffff:127.0.0.1", IPScope.LOOPBACK),  # IPv4-mapped
        ("::ffff:10.0.0.1", IPScope.PRIVATE),
        ("::ffff:8.8.8.8", IPScope.PUBLIC),
        ("2002:7f00:0001::1", IPScope.LOOPBACK),  # 6to4 wrapping 127.0.0.1
        ("2002:0808:0808::1", IPScope.PUBLIC),  # 6to4 wrapping 8.8.8.8
        ("64:ff9b::a00:1", IPScope.PRIVATE),  # NAT64 wrapping 10.0.0.1
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", IPScope.RESERVED),  # Teredo
        ("4000::1", IPScope.RESERVED),  # outside 2000::/3
    ],
)
def test_classify_ip(ip: str, scope: IPScope) -> None:
    assert classify_ip(ipaddress.ip_address(ip)) is scope


def test_is_public_only_for_public() -> None:
    assert is_public_ip(ipaddress.ip_address("9.9.9.9"))
    assert not is_public_ip(ipaddress.ip_address("10.0.0.1"))


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("2130706433", "127.0.0.1"),  # decimal
        ("0x7f000001", "127.0.0.1"),  # hex
        ("0x7f.0.0.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),  # octal
        ("127.1", "127.0.0.1"),  # short form
        ("127.0.1", "127.0.0.1"),
        ("169.254.169.254", "169.254.169.254"),
        ("3232235777", "192.168.1.1"),
    ],
)
def test_loose_ipv4_obfuscations_resolve_to_real_address(host: str, expected: str) -> None:
    assert parse_ipv4_loose(host) == ipaddress.IPv4Address(expected)
    assert parse_ip(host) == ipaddress.IPv4Address(expected)


@pytest.mark.parametrize(
    "host", ["example.com", "256.1.1.1", "1.2.3.4.5", "0xZZ", "", "1..2", "08.0.0.1"]
)
def test_loose_ipv4_rejects_non_addresses(host: str) -> None:
    assert parse_ipv4_loose(host) is None


def test_parse_ip_handles_brackets_and_zone() -> None:
    assert parse_ip("[::1]") == ipaddress.IPv6Address("::1")
    assert parse_ip("fe80::1%eth0") == ipaddress.IPv6Address("fe80::1")
    assert parse_ip("example.com") is None


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "db",
        "printer.local",
        "api.corp.internal",
        "nas.home.arpa",
        "x.test",
        "foo.localhost",
        "intranet",
        "something.onion",
        "1.0.0.127.in-addr.arpa",
    ],
)
def test_hostname_scope_flags_internal_names(host: str) -> None:
    assert hostname_scope(host) is not None


@pytest.mark.parametrize(
    "host", ["example.com", "sub.example.co.uk", "xn--bcher-kva.de", "a.b.c.example.org"]
)
def test_hostname_scope_accepts_public_names(host: str) -> None:
    assert hostname_scope(host) is None
