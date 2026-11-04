from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from hunterintel.config import Settings
from hunterintel.core.cache import MemoryCache
from hunterintel.core.http import HttpGateway
from hunterintel.core.ratelimit import MemoryRateLimiter

_KEY_VARS = [
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "ABUSECH_AUTH_KEY",
    "HUNTERINTEL_API_TOKEN",
    "HUNTERINTEL_DATABASE_URL",
    "HUNTERINTEL_REDIS_URL",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let a developer's real keys/DB leak into the test run."""
    for name in _KEY_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    def _make(**overrides: object) -> Settings:
        base: dict[str, object] = {
            "environment": "test",
            "database_url": "sqlite+aiosqlite:///:memory:",
            "http_timeout_seconds": 3.0,
            "http_connect_timeout_seconds": 2.0,
            "dns_resolvers": ["192.0.2.53"],
        }
        base.update(overrides)
        return Settings(_env_file=None, **base)  # type: ignore[arg-type]

    return _make


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


@pytest.fixture
def make_gateway(settings: Settings) -> Callable[..., HttpGateway]:
    """Gateway wired to an in-process ``httpx.MockTransport`` — no sockets involved."""

    def _make(
        handler: Callable[[httpx.Request], httpx.Response], s: Settings | None = None
    ) -> HttpGateway:
        return HttpGateway(
            s or settings,
            MemoryRateLimiter(),
            MemoryCache(),
            transport=httpx.MockTransport(handler),
        )

    return _make


@pytest.fixture
async def gateway_factory(settings: Settings) -> AsyncIterator[Callable[..., HttpGateway]]:
    created: list[HttpGateway] = []

    def _make(
        handler: Callable[[httpx.Request], httpx.Response], s: Settings | None = None
    ) -> HttpGateway:
        gw = HttpGateway(
            s or settings,
            MemoryRateLimiter(),
            MemoryCache(),
            transport=httpx.MockTransport(handler),
        )
        created.append(gw)
        return gw

    yield _make
    for gw in created:
        await gw.aclose()


@pytest.fixture
def redis_url() -> str:
    url = os.environ.get("HUNTERINTEL_TEST_REDIS_URL")
    if not url:
        pytest.skip("set HUNTERINTEL_TEST_REDIS_URL to run Redis-backed tests")
    return url
