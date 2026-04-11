"""Optional TTL cache wrapper for TokenStore.is_revoked().

Without caching, every authenticated request hits the token store (Redis, DB)
to check revocation. This wrapper adds a cachetools TTLCache in front so that
a token is only looked up once per TTL window.

Security notes:
- Cache only the *positive* result (token is NOT revoked). A revoked token
  must never be served from cache after revocation.
- On ``revoke()`` and ``revoke_all_for_user()``, we invalidate the relevant
  cache entries immediately so revocation takes effect within the same process.
- Cross-process invalidation (multiple workers) still requires the underlying
  store (Redis pub/sub or short TTL). Set ``ttl`` to a value you're comfortable
  with as the worst-case revocation lag across processes (default: 30 s).

Requires ``pip install urauth[cache]``.

Usage::

    from urauth.storage.cache import CachedTokenStore
    from urauth.storage.memory import MemoryTokenStore

    store = CachedTokenStore(MemoryTokenStore(), ttl=30, maxsize=10_000)
"""

from __future__ import annotations

from typing import Any

from urauth.storage.base import TokenStore


class CachedTokenStore:
    """Wraps any :class:`~urauth.storage.base.TokenStore` with a TTL revocation cache.

    Args:
        store: The underlying token store (Redis, memory, DB, etc.).
        ttl: Cache TTL in seconds. Revoked tokens are invalidated immediately
             within this process; across processes the lag is at most *ttl* seconds.
        maxsize: Maximum number of entries in the cache (LRU eviction).
    """

    def __init__(self, store: TokenStore, *, ttl: int = 30, maxsize: int = 10_000) -> None:
        try:
            from cachetools import TTLCache
        except ImportError:
            raise ImportError(
                "cachetools is required for CachedTokenStore. "
                "Install with: pip install urauth[cache]"
            ) from None
        self._store = store
        self._cache: Any = TTLCache(maxsize=maxsize, ttl=ttl)

    async def is_revoked(self, jti: str) -> bool:
        if jti in self._cache:
            return self._cache[jti]
        result = await self._store.is_revoked(jti)
        # Only cache non-revoked results — revoked tokens must not be served
        # stale after the fact within the same process.
        if not result:
            self._cache[jti] = False
        return result

    async def revoke(self, jti: str, expires_at: float) -> None:
        self._cache.pop(jti, None)
        await self._store.revoke(jti, expires_at)

    async def revoke_all_for_user(self, user_id: str) -> None:
        # Invalidate all cached entries for this user by clearing the whole cache.
        # A smarter approach would track jti→user_id, but that adds complexity.
        # For a single-process server this is fine; for multi-process, the TTL
        # is the guard.
        self._cache.clear()
        await self._store.revoke_all_for_user(user_id)

    async def add_token(
        self,
        jti: str,
        user_id: str,
        token_type: str,
        expires_at: float,
        family_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        await self._store.add_token(jti, user_id, token_type, expires_at, family_id, metadata)

    async def get_family_id(self, jti: str) -> str | None:
        return await self._store.get_family_id(jti)

    async def revoke_family(self, family_id: str) -> None:
        self._cache.clear()
        await self._store.revoke_family(family_id)

    async def get_sessions(self, user_id: str) -> list[dict[str, Any]]:
        return await self._store.get_sessions(user_id)
