"""Built-in cache implementations for role data."""

from __future__ import annotations

import json
import time
from typing import Any


class MemoryRoleCache:
    """In-memory cache with TTL tracking. No external dependencies."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[dict[str, Any], float]] = {}

    async def get(self, key: str) -> dict[str, Any] | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    async def set(self, key: str, value: dict[str, Any], ttl: int) -> None:
        self._store[key] = (value, time.monotonic() + ttl)

    async def invalidate(self, key: str) -> None:
        self._store.pop(key, None)


class RedisRoleCache:
    """Redis-backed cache. Requires ``redis.asyncio``."""

    def __init__(self, redis: Any, *, prefix: str = "urauth:roles:") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> dict[str, Any] | None:
        raw = await self._redis.get(self._key(key))
        if raw is None:
            return None
        return json.loads(raw)

    async def set(self, key: str, value: dict[str, Any], ttl: int) -> None:
        await self._redis.set(self._key(key), json.dumps(value), ex=ttl)

    async def invalidate(self, key: str) -> None:
        await self._redis.delete(self._key(key))
