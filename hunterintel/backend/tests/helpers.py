"""Test doubles. Fixtures here are *structural* test inputs, not intelligence data."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from hunterintel.config import Settings
from hunterintel.core.cache import MemoryCache
from hunterintel.core.http import HttpGateway
from hunterintel.core.ratelimit import MemoryRateLimiter
from hunterintel.providers.base import ProviderContext
from hunterintel.providers.dnsclient import DnsAnswer


class FakeDns:
    """Deterministic DNS: ``{(name, rtype): records | DnsAnswer}``; anything else is NOERROR/empty."""

    def __init__(self, table: dict[tuple[str, str], Any] | None = None) -> None:
        self.table = {(n.lower(), t): v for (n, t), v in (table or {}).items()}
        self.calls: list[tuple[str, str]] = []

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rtype)
        self.calls.append(key)
        value = self.table.get(key)
        if value is None:
            return DnsAnswer("NOERROR")
        if isinstance(value, DnsAnswer):
            return value
        return DnsAnswer("NOERROR", list(value), ttl=300)


def make_ctx(
    settings: Settings,
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
    dns: FakeDns | None = None,
    *,
    refresh: bool = False,
) -> ProviderContext:
    def default(req: httpx.Request) -> httpx.Response:  # pragma: no cover - unexpected call
        raise AssertionError(f"unexpected HTTP request: {req.method} {req.url}")

    limiter = MemoryRateLimiter()
    gateway = HttpGateway(
        settings, limiter, MemoryCache(), transport=httpx.MockTransport(handler or default)
    )
    return ProviderContext(
        settings=settings, http=gateway, dns=dns or FakeDns(), limiter=limiter, refresh=refresh
    )  # type: ignore[arg-type]


def json_response(payload: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers)
