"""Small TTL cache for provider responses (memory or Redis).

Caching exists to protect vendor quotas and to keep repeated lookups snappy; it is
**never** used to fabricate results — a cache miss simply means we ask again.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from typing import Any, Protocol

from redis.asyncio import Redis


class Cache(Protocol):
    async def get(self, key: str) -> bytes | None: ...
    async def set(self, key: str, value: bytes, ttl: int) -> None: ...
    async def aclose(self) -> None: ...


class MemoryCache:
    def __init__(self, max_entries: int = 1024) -> None:
        self._data: OrderedDict[str, tuple[float, bytes]] = OrderedDict()
        self._max = max_entries

    async def get(self, key: str) -> bytes | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if expires <= time.monotonic():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return value

    async def set(self, key: str, value: bytes, ttl: int) -> None:
        if ttl <= 0:
            return
        self._data[key] = (time.monotonic() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    async def aclose(self) -> None:
        self._data.clear()


class RedisCache:
    def __init__(self, client: Redis, prefix: str = "hunterintel:cache:") -> None:
        self._client = client
        self._prefix = prefix

    async def get(self, key: str) -> bytes | None:
        value = await self._client.get(self._prefix + key)
        return bytes(value) if value is not None else None

    async def set(self, key: str, value: bytes, ttl: int) -> None:
        if ttl > 0:
            await self._client.set(self._prefix + key, value, ex=ttl)

    async def aclose(self) -> None:
        return None


async def get_json(cache: Cache, key: str) -> Any | None:
    raw = await cache.get(key)
    return None if raw is None else json.loads(raw)


async def set_json(cache: Cache, key: str, value: Any, ttl: int) -> None:
    await cache.set(key, json.dumps(value, separators=(",", ":")).encode(), ttl)
