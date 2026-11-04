"""Network destination policy: which addresses and names may we talk to?

This module is pure (no I/O) so it can be unit-tested exhaustively. It is used in
two places:

* by :mod:`hunterintel.core.http` at **connect time**, to refuse any destination that
  is not a public, globally routable address (SSRF protection), and
* by the indicator layer, to explain to the analyst *why* a remote lookup was
  skipped for an address such as ``10.0.0.5`` or a name like ``fileserver.corp``.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class IPScope(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CGNAT = "cgnat"
    MULTICAST = "multicast"
    DOCUMENTATION = "documentation"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"


_V4_TABLE: list[tuple[ipaddress.IPv4Network, IPScope]] = [
    (ipaddress.IPv4Network("0.0.0.0/8"), IPScope.UNSPECIFIED),
    (ipaddress.IPv4Network("10.0.0.0/8"), IPScope.PRIVATE),
    (ipaddress.IPv4Network("100.64.0.0/10"), IPScope.CGNAT),
    (ipaddress.IPv4Network("127.0.0.0/8"), IPScope.LOOPBACK),
    (ipaddress.IPv4Network("169.254.0.0/16"), IPScope.LINK_LOCAL),
    (ipaddress.IPv4Network("172.16.0.0/12"), IPScope.PRIVATE),
    (ipaddress.IPv4Network("192.0.0.0/24"), IPScope.RESERVED),
    (ipaddress.IPv4Network("192.0.2.0/24"), IPScope.DOCUMENTATION),
    (ipaddress.IPv4Network("192.88.99.0/24"), IPScope.RESERVED),
    (ipaddress.IPv4Network("192.168.0.0/16"), IPScope.PRIVATE),
    (ipaddress.IPv4Network("198.18.0.0/15"), IPScope.RESERVED),
    (ipaddress.IPv4Network("198.51.100.0/24"), IPScope.DOCUMENTATION),
    (ipaddress.IPv4Network("203.0.113.0/24"), IPScope.DOCUMENTATION),
    (ipaddress.IPv4Network("224.0.0.0/4"), IPScope.MULTICAST),
    (ipaddress.IPv4Network("240.0.0.0/4"), IPScope.RESERVED),
]

_V6_TABLE: list[tuple[ipaddress.IPv6Network, IPScope]] = [
    (ipaddress.IPv6Network("::/128"), IPScope.UNSPECIFIED),
    (ipaddress.IPv6Network("::1/128"), IPScope.LOOPBACK),
    (ipaddress.IPv6Network("100::/64"), IPScope.RESERVED),  # discard-only
    (ipaddress.IPv6Network("2001::/32"), IPScope.RESERVED),  # Teredo
    (ipaddress.IPv6Network("2001:10::/28"), IPScope.RESERVED),  # ORCHID
    (ipaddress.IPv6Network("2001:20::/28"), IPScope.RESERVED),  # ORCHIDv2
    (ipaddress.IPv6Network("2001:db8::/32"), IPScope.DOCUMENTATION),
    (ipaddress.IPv6Network("fc00::/7"), IPScope.PRIVATE),  # unique local
    (ipaddress.IPv6Network("fe80::/10"), IPScope.LINK_LOCAL),
    (ipaddress.IPv6Network("fec0::/10"), IPScope.PRIVATE),  # deprecated site-local
    (ipaddress.IPv6Network("ff00::/8"), IPScope.MULTICAST),
]

_V6_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.IPv6Network("2002::/16")


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return an IPv4 address tunnelled inside an IPv6 one (mapped / 6to4 / NAT64)."""
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr in _SIXTOFOUR and addr.sixtofour is not None:
        return addr.sixtofour
    if addr in _NAT64:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def classify_ip(addr: IPAddress) -> IPScope:
    """Classify an IP address. Only :attr:`IPScope.PUBLIC` is safe to contact."""
    if isinstance(addr, ipaddress.IPv4Address):
        for net, scope in _V4_TABLE:
            if addr in net:
                return scope
        return IPScope.PUBLIC if addr.is_global else IPScope.RESERVED

    embedded = _embedded_ipv4(addr)
    if embedded is not None:
        # A tunnelled address inherits the scope of the IPv4 address it carries.
        return classify_ip(embedded)
    for net, scope in _V6_TABLE:
        if addr in net:
            return scope
    if addr not in _V6_GLOBAL_UNICAST:
        return IPScope.RESERVED
    return IPScope.PUBLIC if addr.is_global else IPScope.RESERVED


def is_public_ip(addr: IPAddress) -> bool:
    return classify_ip(addr) is IPScope.PUBLIC


_NUMERIC_PART = re.compile(r"^(0x[0-9a-f]+|[0-9]+)$", re.IGNORECASE)


def parse_ipv4_loose(host: str) -> ipaddress.IPv4Address | None:
    """Parse the legacy ``inet_aton`` spellings that browsers/libc accept.

    ``2130706433``, ``0x7f.1``, ``0177.0.0.1`` and ``127.1`` all mean loopback. They are
    a classic way to smuggle internal targets past naive string filters, so we resolve
    them to the real address before applying policy (and flag them as obfuscation).
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(not _NUMERIC_PART.match(p) for p in parts):
        return None
    nums: list[int] = []
    for part in parts:
        if part.lower().startswith("0x"):
            nums.append(int(part, 16))
        elif len(part) > 1 and part.startswith("0"):
            try:
                nums.append(int(part, 8))
            except ValueError:
                return None
        else:
            nums.append(int(part, 10))
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = 0
    for n in head:
        value = (value << 8) | n
    value = (value << (8 * (4 - len(head)))) | last
    return ipaddress.IPv4Address(value)


def parse_ip(host: str) -> IPAddress | None:
    """Parse a host string as an IP address (strict forms first, then legacy IPv4)."""
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    candidate = candidate.split("%", 1)[0]  # drop IPv6 zone id
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    return parse_ipv4_loose(candidate)


# ── hostnames ────────────────────────────────────────────────────────────────

#: Special-use / non-public suffixes (RFC 6761, RFC 6762, RFC 8375 and common
#: private-network conventions). Remote lookups for these are pointless and would
#: leak internal naming to third parties.
INTERNAL_SUFFIXES: tuple[str, ...] = (
    "localhost",
    "local",
    "localdomain",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "private",
    "home.arpa",
    "test",
    "invalid",
    "example",
    "onion",
    "in-addr.arpa",
    "ip6.arpa",
)


def hostname_scope(host: str) -> str | None:
    """Return a reason string if ``host`` is not a public DNS name, else ``None``."""
    name = host.strip().rstrip(".").lower()
    if not name:
        return "empty hostname"
    if "." not in name:
        return "single-label hostname (not a public DNS name)"
    for suffix in INTERNAL_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            return f"special-use or internal suffix '.{suffix}'"
    return None
