"""Test doubles. Fixtures here are *structural* test inputs, not intelligence data."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

from hunterintel.config import Settings
from hunterintel.core.cache import MemoryCache
from hunterintel.core.http import HttpGateway
from hunterintel.core.ratelimit import MemoryRateLimiter
from hunterintel.db.models import Base
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


TEST_DB_ENV = "HUNTERINTEL_TEST_DATABASE_URL"


async def fresh_database_url(tmp_path: Path, name: str) -> str:
    """SQLite file per test by default; or an empty schema on the database named by
    ``HUNTERINTEL_TEST_DATABASE_URL`` (e.g. ``postgresql+asyncpg://…``) so the very same suite
    can verify other databases."""
    url = os.environ.get(TEST_DB_ENV)
    if not url:
        return f"sqlite+aiosqlite:///{tmp_path}/{name}.db"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    await engine.dispose()
    return url
