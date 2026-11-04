from __future__ import annotations

import asyncio
import time

import pytest
from redis.asyncio import Redis

from hunterintel.core.cache import MemoryCache, RedisCache, get_json, set_json
from hunterintel.core.ratelimit import (
    MemoryRateLimiter,
    RateLimitedError,
    RateSpec,
    RedisRateLimiter,
    wait_for_slot,
)
from hunterintel.core.redact import redact


def test_ratespec_parse() -> None:
    assert RateSpec.parse("4/60") == RateSpec(4, 60.0)
    for bad in ("", "4", "a/b", "0/5", "5/0"):
        with pytest.raises(ValueError):
            RateSpec.parse(bad)


async def test_memory_limiter_allows_then_blocks_then_recovers() -> None:
    rl = MemoryRateLimiter()
    spec = RateSpec(2, 0.3)
    assert await rl.acquire("k", spec) == 0
    assert await rl.acquire("k", spec) == 0
    wait = await rl.acquire("k", spec)
    assert 0 < wait <= 0.3
    assert await rl.acquire("other", spec) == 0  # keys are independent
    await asyncio.sleep(0.32)
    assert await rl.acquire("k", spec) == 0


async def test_wait_for_slot_smooths_short_bursts_and_fails_long_ones() -> None:
    rl = MemoryRateLimiter()
    spec = RateSpec(1, 0.2)
    await wait_for_slot(rl, "k", spec)
    t0 = time.monotonic()
    await wait_for_slot(rl, "k", spec, max_wait=2)
    assert time.monotonic() - t0 >= 0.15
    with pytest.raises(RateLimitedError) as err:
        await wait_for_slot(rl, "k", RateSpec(1, 3600), max_wait=0.1)
        await wait_for_slot(rl, "k", RateSpec(1, 3600), max_wait=0.1)
    assert err.value.retry_after > 1


async def test_memory_cache_ttl_and_eviction() -> None:
    c = MemoryCache(max_entries=2)
    await c.set("a", b"1", 60)
    await c.set("b", b"2", 60)
    await c.set("c", b"3", 60)
    assert await c.get("a") is None  # evicted
    assert await c.get("c") == b"3"
    await c.set("short", b"x", 1)
    c._data["short"] = (time.monotonic() - 1, b"x")  # expire it
    assert await c.get("short") is None
    await c.set("zero", b"x", 0)
    assert await c.get("zero") is None
    await set_json(c, "j", {"a": [1, 2]}, 60)
    assert await get_json(c, "j") == {"a": [1, 2]}


async def test_redis_limiter_is_shared_across_instances(redis_url: str) -> None:
    client = Redis.from_url(redis_url)
    await client.flushdb()
    a, b = RedisRateLimiter(client, "t:"), RedisRateLimiter(client, "t:")  # two "workers"
    spec = RateSpec(3, 1.0)
    grants = [await a.acquire("vt", spec), await b.acquire("vt", spec), await a.acquire("vt", spec)]
    assert grants == [0.0, 0.0, 0.0]
    wait = await b.acquire("vt", spec)
    assert 0 < wait <= 1.0
    await asyncio.sleep(1.05)
    assert await b.acquire("vt", spec) == 0.0
    await client.flushdb()
    await client.aclose()


async def test_redis_cache_roundtrip_and_expiry(redis_url: str) -> None:
    client = Redis.from_url(redis_url)
    cache = RedisCache(client, "t:")
    await cache.set("k", b"v", 1)
    assert await cache.get("k") == b"v"
    await asyncio.sleep(1.1)
    assert await cache.get("k") is None
    await client.aclose()


def test_redact_removes_known_and_shaped_secrets() -> None:
    text = "failed: x-apikey: abcdef1234567890 and Authorization: Bearer tok_ABCDEF123456 plus MYSECRETVALUE"
    out = redact(text, ["MYSECRETVALUE"])
    assert (
        "abcdef1234567890" not in out
        and "tok_ABCDEF123456" not in out
        and "MYSECRETVALUE" not in out
    )
    assert redact("nothing to see here") == "nothing to see here"
