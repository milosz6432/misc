"""DNS access behind a small interface so providers are testable without a network."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from hunterintel.config import Settings
from hunterintel.core.ratelimit import MemoryRateLimiter, RateLimiter, RateSpec, wait_for_slot


@dataclass
class DnsAnswer:
    """Outcome of one query. ``rcode`` is a short status, not an exception."""

    rcode: str  # NOERROR | NXDOMAIN | SERVFAIL | TIMEOUT | ERROR
    records: list[Any] = field(default_factory=list)
    ttl: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.rcode in ("NOERROR", "NXDOMAIN")


class DnsClient(Protocol):
    async def query(self, name: str, rtype: str) -> DnsAnswer: ...


def _strip(name: str) -> str:
    return name.rstrip(".").lower()


def _convert(rtype: str, rdata: Any) -> Any:
    """Turn dnspython rdata into plain, JSON-friendly values."""
    if rtype in ("A", "AAAA"):
        return rdata.address
    if rtype in ("NS", "CNAME", "PTR"):
        return _strip(rdata.target.to_text())
    if rtype == "MX":
        return {"preference": rdata.preference, "exchange": _strip(rdata.exchange.to_text())}
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rtype == "SOA":
        return {
            "mname": _strip(rdata.mname.to_text()),
            "rname": _strip(rdata.rname.to_text()),
            "serial": rdata.serial,
            "refresh": rdata.refresh,
            "retry": rdata.retry,
            "expire": rdata.expire,
            "minimum": rdata.minimum,
        }
    if rtype == "CAA":
        return {
            "flags": rdata.flags,
            "tag": rdata.tag.decode("ascii", "replace"),
            "value": rdata.value.decode("utf-8", "replace"),
        }
    return rdata.to_text()


class DnsPythonClient:
    """Resolver using the configured public resolvers (not the container's own)."""

    def __init__(self, settings: Settings, limiter: RateLimiter | None = None) -> None:
        self._settings = settings
        self._limiter = limiter or MemoryRateLimiter()
        self._sem = asyncio.Semaphore(8)

    def _resolver(self) -> dns.asyncresolver.Resolver:
        if self._settings.dns_resolvers:
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = list(self._settings.dns_resolvers)
        else:
            resolver = dns.asyncresolver.Resolver(configure=True)
        resolver.lifetime = self._settings.dns_timeout_seconds
        resolver.timeout = max(self._settings.dns_timeout_seconds / 2, 0.5)
        return resolver

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        await wait_for_slot(self._limiter, "dns", RateSpec(100, 1.0), max_wait=5.0)
        async with self._sem:
            try:
                answer = await self._resolver().resolve(name, rtype, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                return DnsAnswer("NXDOMAIN")
            except dns.resolver.NoNameservers as exc:
                return DnsAnswer("SERVFAIL", error=str(exc)[:200])
            except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
                return DnsAnswer("TIMEOUT", error="resolver timed out")
            except (dns.exception.DNSException, OSError) as exc:
                return DnsAnswer("ERROR", error=f"{type(exc).__name__}: {str(exc)[:160]}")
        if answer.rrset is None:
            return DnsAnswer("NOERROR")
        records = [_convert(rtype, rd) for rd in answer]
        return DnsAnswer("NOERROR", records, ttl=answer.rrset.ttl)
