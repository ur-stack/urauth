from __future__ import annotations

from urauth.backends.base import TokenStore


class RevocationService:
    """Thin facade over a TokenStore for revocation operations."""

    def __init__(self, store: TokenStore) -> None:
        self._store = store

    async def is_revoked(self, jti: str) -> bool:
        return await self._store.is_revoked(jti)

    async def revoke(self, jti: str, expires_at: float) -> None:
        await self._store.revoke(jti, expires_at)

    async def revoke_all_for_user(self, user_id: str) -> None:
        await self._store.revoke_all_for_user(user_id)
