# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportGeneralTypeIssues=false
"""Redis-backed session store (optional dependency)."""

from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis  # pyright: ignore[reportMissingImports]


class RedisSessionStore:
    """Server-side session storage backed by Redis."""

    def __init__(self, redis: Redis, prefix: str = "session:") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def _user_key(self, user_id: str) -> str:
        return f"{self._prefix}user:{user_id}"

    async def create(self, session_id: str, user_id: str, data: dict[str, Any], ttl: int) -> None:
        payload = json.dumps({"user_id": user_id, "data": data})
        pipe = self._redis.pipeline()
        pipe.setex(self._key(session_id), ttl, payload)
        pipe.sadd(self._user_key(user_id), session_id)
        pipe.expire(self._user_key(user_id), ttl)
        await pipe.execute()

    async def get(self, session_id: str) -> dict[str, Any] | None:
        raw = await self._redis.get(self._key(session_id))
        if raw is None:
            return None
        return json.loads(raw)

    async def delete(self, session_id: str) -> None:
        raw = await self._redis.get(self._key(session_id))
        if raw:
            data = json.loads(raw)
            await self._redis.srem(self._user_key(data["user_id"]), session_id)
        await self._redis.delete(self._key(session_id))

    async def delete_all_for_user(self, user_id: str) -> None:
        sids = await self._redis.smembers(self._user_key(user_id))
        if sids:
            pipe = self._redis.pipeline()
            for sid in sids:
                pipe.delete(self._key(sid.decode() if isinstance(sid, bytes) else sid))
            pipe.delete(self._user_key(user_id))
            await pipe.execute()
