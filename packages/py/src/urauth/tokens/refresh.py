from __future__ import annotations

import uuid

from urauth.storage.base import TokenStore
from urauth.config import AuthConfig
from urauth.exceptions import TokenRevokedError
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPair


class RefreshService:
    """Handles refresh-token rotation with reuse detection."""

    def __init__(
        self,
        token_service: TokenService,
        token_store: TokenStore,
        config: AuthConfig,
    ) -> None:
        self._tokens = token_service
        self._store = token_store
        self._config = config

    async def rotate(self, raw_refresh_token: str) -> TokenPair:
        """Validate, revoke old token, issue new pair.

        If the old token was already revoked (reuse detected), revoke the
        entire token family to mitigate stolen-token replay.
        """
        claims = self._tokens.validate_refresh_token(raw_refresh_token)
        jti = claims["jti"]
        user_id = claims["sub"]

        # Reuse detection: if already revoked, someone replayed a stolen token
        if await self._store.is_revoked(jti):
            family_id = await self._store.get_family_id(jti)
            if family_id:
                await self._store.revoke_family(family_id)
            else:
                await self._store.revoke_all_for_user(user_id)
            raise TokenRevokedError("Refresh token reuse detected — all tokens revoked")

        # Revoke the old refresh token
        await self._store.revoke(jti, claims["exp"])

        # Issue new pair within the same family
        family_id = claims.get("family_id") or await self._store.get_family_id(jti) or uuid.uuid4().hex

        pair = self._tokens.create_token_pair(user_id, family_id=family_id)

        # Track the new tokens
        access_claims = self._tokens.decode_token(pair.access_token)
        refresh_claims = self._tokens.decode_token(pair.refresh_token)

        await self._store.add_token(
            jti=access_claims["jti"],
            user_id=user_id,
            token_type="access",
            expires_at=access_claims["exp"],
            family_id=family_id,
        )
        await self._store.add_token(
            jti=refresh_claims["jti"],
            user_id=user_id,
            token_type="refresh",
            expires_at=refresh_claims["exp"],
            family_id=family_id,
        )

        return pair
