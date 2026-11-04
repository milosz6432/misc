"""Application container and FastAPI dependencies."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
from fastapi import Depends, HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from hunterintel.config import Settings
from hunterintel.core.cache import Cache, MemoryCache, RedisCache
from hunterintel.core.http import HttpGateway
from hunterintel.core.ratelimit import MemoryRateLimiter, RateLimiter, RateSpec, RedisRateLimiter
from hunterintel.db.session import create_engine, create_session_factory
from hunterintel.providers.base import ProviderRegistry
from hunterintel.providers.dnsclient import DnsClient, DnsPythonClient
from hunterintel.providers.registry import build_registry
from hunterintel.services.enrichment import EnrichmentService


@dataclass
class Container:
    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    limiter: RateLimiter
    cache: Cache
    redis: Redis | None
    http: HttpGateway
    dns: DnsClient
    registry: ProviderRegistry
    enrichment: EnrichmentService

    async def aclose(self) -> None:
        await self.http.aclose()
        if self.redis is not None:
            await self.redis.aclose()
        await self.engine.dispose()


def build_container(
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    dns: DnsClient | None = None,
) -> Container:
    """Wire the application. ``transport`` / ``dns`` exist so tests can run offline."""
    redis: Redis | None = Redis.from_url(settings.redis_url) if settings.redis_url else None
    limiter: RateLimiter = RedisRateLimiter(redis) if redis else MemoryRateLimiter()
    cache: Cache = RedisCache(redis) if redis else MemoryCache()
    engine = create_engine(settings)
    http = HttpGateway(settings, limiter, cache, transport=transport)
    dns_client = dns or DnsPythonClient(settings, limiter)
    registry = build_registry(settings)
    return Container(
        settings=settings,
        engine=engine,
        session_factory=create_session_factory(engine),
        limiter=limiter,
        cache=cache,
        redis=redis,
        http=http,
        dns=dns_client,
        registry=registry,
        enrichment=EnrichmentService(settings, registry, http, dns_client, limiter),
    )


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


async def get_session(c: Container = Depends(get_container)) -> AsyncIterator[AsyncSession]:
    async with c.session_factory() as session:
        yield session


async def require_auth(request: Request, c: Container = Depends(get_container)) -> None:
    """Optional bearer-token authentication (constant-time comparison)."""
    token = c.settings.api_token
    if token is None:
        return
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    expected = token.get_secret_value().encode()
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), expected):
        raise HTTPException(
            status_code=401,
            detail={"code": "unauthorized", "message": "A valid bearer token is required."},
            headers={"WWW-Authenticate": "Bearer"},
        )


async def _limit(request: Request, c: Container, bucket: str, spec: RateSpec) -> None:
    client = request.client.host if request.client else "unknown"
    wait = await c.limiter.acquire(f"inbound:{bucket}:{client}", spec)
    if wait > 0:
        raise HTTPException(
            status_code=429,
            detail={"code": "rate_limited", "message": "Too many requests; slow down."},
            headers={"Retry-After": str(max(int(wait) + 1, 1))},
        )


async def inbound_limit(request: Request, c: Container = Depends(get_container)) -> None:
    await _limit(request, c, "api", RateSpec(c.settings.inbound_rate_limit_per_minute, 60.0))


async def enrich_limit(request: Request, c: Container = Depends(get_container)) -> None:
    """Enrichment spends third-party quota, so it gets a much tighter budget."""
    await _limit(
        request, c, "enrich", RateSpec(max(c.settings.inbound_rate_limit_per_minute // 8, 5), 60.0)
    )
