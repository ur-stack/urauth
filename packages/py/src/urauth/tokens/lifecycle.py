"""Unified token lifecycle: issue, validate, refresh, revoke.

Consolidates TokenService, RefreshService, and TokenStore coordination
into a single entry point so callers never manually orchestrate token
creation, tracking, and revocation across multiple objects.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from urauth.backends.base import TokenStore
from urauth.config import AuthConfig
from urauth.exceptions import InvalidTokenError, TokenExpiredError, TokenRevokedError, UnauthorizedError
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPayload


@dataclass(frozen=True, slots=True)
class IssueRequest:
    """What callers provide when issuing tokens (login, OAuth callback, etc.)."""

    user_id: str
    roles: list[str] | None = None
    scopes: list[str] | None = None
    tenant_id: str | None = None
    fresh: bool = False
    extra_claims: dict[str, Any] | None = None
    session_metadata: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class IssuedTokenPair:
    """Token pair enriched with family_id for session reference."""

    access_token: str
    refresh_token: str
    family_id: str
    token_type: str = "bearer"


class TokenLifecycle:
    """Single entry point for all token operations.

    Coordinates JWT creation/validation (TokenService) with
    revocation/family tracking (TokenStore) so callers never
    touch both directly.
    """

    def __init__(
        self,
        config: AuthConfig,
        token_store: TokenStore,
    ) -> None:
        self._config = config
        self.store = token_store
        self._token_service = TokenService(config)

    @property
    def jwt(self) -> TokenService:
        """Escape hatch: direct access to the underlying TokenService
        for advanced use cases (custom token types, raw decode, etc.)."""
        return self._token_service

    # ── Issue (login) ─────────────────────────────────────────

    async def issue(self, request: IssueRequest) -> IssuedTokenPair:
        """Create an access+refresh token pair, register both in the store.

        Handles family ID generation, claim building, and store tracking
        internally. This is the ONE call for login.
        """
        family_id = uuid.uuid4().hex

        # Create the JWT pair
        pair = self._token_service.create_token_pair(
            request.user_id,
            scopes=request.scopes,
            roles=request.roles,
            tenant_id=request.tenant_id,
            fresh=request.fresh,
            extra_claims=request.extra_claims,
            family_id=family_id,
        )

        # Track both tokens — decode to get JTI/exp for store
        access_claims = self._token_service.decode_token(pair.access_token)
        refresh_claims = self._token_service.decode_token(pair.refresh_token)

        await self.store.add_token(
            jti=access_claims["jti"],
            user_id=request.user_id,
            token_type="access",
            expires_at=access_claims["exp"],
            family_id=family_id,
            metadata=request.session_metadata,
        )
        await self.store.add_token(
            jti=refresh_claims["jti"],
            user_id=request.user_id,
            token_type="refresh",
            expires_at=refresh_claims["exp"],
            family_id=family_id,
        )

        return IssuedTokenPair(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            family_id=family_id,
        )

    # ── Refresh (rotate) ─────────────────────────────────────

    async def refresh(self, raw_refresh_token: str) -> IssuedTokenPair:
        """Rotate a refresh token: validate, revoke old, issue new pair.

        Performs reuse detection internally — if the refresh token was
        already consumed, revokes the entire family and raises
        TokenRevokedError.
        """
        claims = self._token_service.validate_refresh_token(raw_refresh_token)
        jti = claims["jti"]
        user_id = claims["sub"]

        # Reuse detection: if already revoked, someone replayed a stolen token
        if await self.store.is_revoked(jti):
            family_id = await self.store.get_family_id(jti)
            if family_id:
                await self.store.revoke_family(family_id)
            else:
                await self.store.revoke_all_for_user(user_id)
            raise TokenRevokedError("Refresh token reuse detected — all tokens revoked")

        # Revoke the old refresh token
        await self.store.revoke(jti, claims["exp"])

        # Issue new pair within the same family
        family_id = claims.get("family_id") or await self.store.get_family_id(jti) or uuid.uuid4().hex

        pair = self._token_service.create_token_pair(user_id, family_id=family_id)

        # Track the new tokens
        access_claims = self._token_service.decode_token(pair.access_token)
        refresh_claims = self._token_service.decode_token(pair.refresh_token)

        await self.store.add_token(
            jti=access_claims["jti"],
            user_id=user_id,
            token_type="access",
            expires_at=access_claims["exp"],
            family_id=family_id,
        )
        await self.store.add_token(
            jti=refresh_claims["jti"],
            user_id=user_id,
            token_type="refresh",
            expires_at=refresh_claims["exp"],
            family_id=family_id,
        )

        return IssuedTokenPair(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            family_id=family_id,
        )

    # ── Revoke (logout) ──────────────────────────────────────

    async def revoke(self, raw_token: str) -> None:
        """Revoke the session (family) associated with this token.

        Silently handles expired/invalid tokens — logout should not fail.
        """
        try:
            claims = self._token_service.decode_token(raw_token)
        except (InvalidTokenError, TokenExpiredError):
            return

        family_id = await self.store.get_family_id(claims["jti"])
        if family_id:
            await self.store.revoke_family(family_id)
        else:
            await self.store.revoke(claims["jti"], claims["exp"])

    async def revoke_all(self, user_id: str) -> None:
        """Revoke ALL tokens for a user (global logout, password change, account disable)."""
        await self.store.revoke_all_for_user(user_id)

    # ── Validate (middleware / build_context) ─────────────────

    async def validate(self, raw_access_token: str) -> TokenPayload:
        """Validate an access token: verify JWT + check revocation in one call.

        Raises InvalidTokenError, TokenExpiredError, or UnauthorizedError.
        """
        payload = self._token_service.validate_access_token(raw_access_token)

        if await self.store.is_revoked(payload.jti):
            raise UnauthorizedError("Token has been revoked")

        return payload
