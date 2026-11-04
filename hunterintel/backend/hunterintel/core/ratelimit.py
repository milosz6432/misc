"""Rate limiting for outbound provider calls and inbound API traffic.

Two interchangeable back-ends implement :class:`RateLimiter`:

* :class:`MemoryRateLimiter` — per-process sliding window. Right for a single worker.
* :class:`RedisRateLimiter` — a Lua-scripted sliding window held in Redis, so the limit is
  shared across API workers/containers. Redis is justified *only* here and in the
  response cache: with several workers an in-process limiter would multiply a vendor's
  free-tier quota by the worker count and get the API key suspended.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Protocol

from redis.asyncio import Redis


class RateLimitedError(Exception):
    """Raised when a slot cannot be obtained within the allowed wait."""

    def __init__(self, key: str, retry_after: float) -> None:
        super().__init__(f"rate limit for '{key}' exceeded; retry in {retry_after:.1f}s")
        self.key = key
        self.retry_after = retry_after


@dataclass(frozen=True)
class RateSpec:
    """``requests`` allowed per ``per_seconds`` sliding window."""

    requests: int
    per_seconds: float

    def __post_init__(self) -> None:
        if self.requests < 1 or self.per_seconds <= 0:
            raise ValueError("RateSpec requires requests >= 1 and per_seconds > 0")

    @classmethod
    def parse(cls, text: str) -> RateSpec:
        """Parse ``"4/60"`` (4 requests per 60 seconds)."""
        try:
            requests, seconds = text.split("/", 1)
            return cls(int(requests), float(seconds))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid rate spec {text!r}; expected 'requests/seconds'") from exc


class RateLimiter(Protocol):
    async def acquire(self, key: str, spec: RateSpec) -> float:
        """Try to take a slot. Return ``0.0`` if granted, else seconds until one frees up."""
        ...

    async def aclose(self) -> None: ...


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, key: str, spec: RateSpec) -> float:
        async with self._lock:
            now = time.monotonic()
            window = self._events.setdefault(key, deque())
            while window and window[0] <= now - spec.per_seconds:
                window.popleft()
            if len(window) < spec.requests:
                window.append(now)
                return 0.0
            return max(window[0] + spec.per_seconds - now, 0.001)

    async def aclose(self) -> None:
        self._events.clear()


_LUA_SLIDING_WINDOW = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
if redis.call('ZCARD', KEYS[1]) < limit then
  redis.call('ZADD', KEYS[1], now, ARGV[3])
  redis.call('PEXPIRE', KEYS[1], math.ceil(window * 1000) + 1000)
  return '0'
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
return tostring(tonumber(oldest[2]) + window - now)
"""


class RedisRateLimiter:
    def __init__(self, client: Redis, prefix: str = "hunterintel:rl:") -> None:
        self._client = client
        self._prefix = prefix
        self._script = client.register_script(_LUA_SLIDING_WINDOW)

    async def acquire(self, key: str, spec: RateSpec) -> float:
        result = await self._script(
            keys=[self._prefix + key],
            args=[spec.per_seconds, spec.requests, uuid.uuid4().hex],
        )
        if isinstance(result, bytes):
            result = result.decode()
        return max(float(result), 0.0)

    async def aclose(self) -> None:  # the client is owned by the application container
        return None


async def wait_for_slot(
    limiter: RateLimiter, key: str, spec: RateSpec, *, max_wait: float = 15.0
) -> None:
    """Block until the limiter grants a slot, or raise :class:`RateLimitedError`.

    Short waits are absorbed (so a burst of lookups is smoothed rather than failed);
    waits beyond ``max_wait`` surface to the analyst as a ``rate_limited`` provider run.
    """
    deadline = time.monotonic() + max_wait
    while True:
        wait = await limiter.acquire(key, spec)
        if wait <= 0:
            return
        if time.monotonic() + wait > deadline:
            raise RateLimitedError(key, wait)
        await asyncio.sleep(min(wait, max_wait))
