"""Tests for refresh-token rotation and reuse detection."""

from __future__ import annotations

import pytest

from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.exceptions import TokenRevokedError
from urauth.tokens.jwt import TokenService
from urauth.tokens.refresh import RefreshService


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key="test-secret")


@pytest.fixture
def token_service(config: AuthConfig) -> TokenService:
    return TokenService(config)


@pytest.fixture
def store() -> MemoryTokenStore:
    return MemoryTokenStore()


@pytest.fixture
def refresh_svc(token_service: TokenService, store: MemoryTokenStore, config: AuthConfig) -> RefreshService:
    return RefreshService(token_service, store, config)


class TestRefreshRotation:
    @pytest.mark.asyncio
    async def test_rotate_issues_new_pair(
        self, refresh_svc: RefreshService, token_service: TokenService, store: MemoryTokenStore
    ) -> None:
        # Create initial refresh token and track it
        original = token_service.create_refresh_token("user-1", family_id="fam-1")
        claims = token_service.validate_refresh_token(original)
        await store.add_token(
            jti=claims["jti"],
            user_id="user-1",
            token_type="refresh",
            expires_at=claims["exp"],
            family_id="fam-1",
        )

        pair = await refresh_svc.rotate(original)
        assert pair.access_token
        assert pair.refresh_token

        # Old token should be revoked
        assert await store.is_revoked(claims["jti"])

    @pytest.mark.asyncio
    async def test_reuse_detection_revokes_family(
        self, refresh_svc: RefreshService, token_service: TokenService, store: MemoryTokenStore
    ) -> None:
        # Create and track initial token
        original = token_service.create_refresh_token("user-1", family_id="fam-1")
        claims = token_service.validate_refresh_token(original)
        await store.add_token(
            jti=claims["jti"],
            user_id="user-1",
            token_type="refresh",
            expires_at=claims["exp"],
            family_id="fam-1",
        )

        # First rotation succeeds
        await refresh_svc.rotate(original)

        # Reuse of the same (now-revoked) token triggers family revocation
        with pytest.raises(TokenRevokedError, match="reuse detected"):
            await refresh_svc.rotate(original)
