"""Security-focused refresh token tests — double rotation, family isolation, reuse attacks."""

from __future__ import annotations

import pytest

from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.exceptions import TokenRevokedError
from urauth.tokens.jwt import TokenService
from urauth.tokens.refresh import RefreshService

SECRET = "test-secret-key-32-chars-long-xx"


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key=SECRET)


@pytest.fixture
def token_service(config: AuthConfig) -> TokenService:
    return TokenService(config)


@pytest.fixture
def store() -> MemoryTokenStore:
    return MemoryTokenStore()


@pytest.fixture
def refresh_svc(token_service: TokenService, store: MemoryTokenStore, config: AuthConfig) -> RefreshService:
    return RefreshService(token_service, store, config)


async def _create_tracked_refresh(
    token_service: TokenService, store: MemoryTokenStore, user_id: str, family_id: str
) -> str:
    """Helper: create a refresh token and track it in the store."""
    token = token_service.create_refresh_token(user_id, family_id=family_id)
    claims = token_service.validate_refresh_token(token)
    await store.add_token(
        jti=claims["jti"],
        user_id=user_id,
        token_type="refresh",
        expires_at=claims["exp"],
        family_id=family_id,
    )
    return token


class TestDoubleRotationAttack:
    async def test_replaying_old_token_revokes_entire_family(
        self,
        refresh_svc: RefreshService,
        token_service: TokenService,
        store: MemoryTokenStore,
    ) -> None:
        """Attacker captures token, legitimate user rotates, attacker replays → family revoked."""
        original = await _create_tracked_refresh(token_service, store, "user-1", "fam-1")

        # Legitimate rotation
        pair2 = await refresh_svc.rotate(original)

        # Attacker replays old (now-revoked) token
        with pytest.raises(TokenRevokedError, match="reuse detected"):
            await refresh_svc.rotate(original)

        # Even the legitimately rotated tokens are now revoked
        new_refresh_claims = token_service.decode_token(pair2.refresh_token)
        assert await store.is_revoked(new_refresh_claims["jti"]) is True

        new_access_claims = token_service.decode_token(pair2.access_token)
        assert await store.is_revoked(new_access_claims["jti"]) is True


class TestFamilyIsolation:
    async def test_revoking_family_a_does_not_affect_family_b(
        self,
        refresh_svc: RefreshService,
        token_service: TokenService,
        store: MemoryTokenStore,
    ) -> None:
        token_a = await _create_tracked_refresh(token_service, store, "user-1", "fam-a")
        token_b = await _create_tracked_refresh(token_service, store, "user-1", "fam-b")

        # Rotate A, then replay A → family A revoked
        await refresh_svc.rotate(token_a)
        with pytest.raises(TokenRevokedError):
            await refresh_svc.rotate(token_a)

        # Family B should still work
        pair_b = await refresh_svc.rotate(token_b)
        assert pair_b.access_token
        assert pair_b.refresh_token


class TestRotateAfterUserRevocation:
    async def test_rotate_after_revoke_all_for_user(
        self,
        refresh_svc: RefreshService,
        token_service: TokenService,
        store: MemoryTokenStore,
    ) -> None:
        token = await _create_tracked_refresh(token_service, store, "user-1", "fam-1")

        await store.revoke_all_for_user("user-1")

        # Token is now revoked — rotation should detect reuse
        with pytest.raises(TokenRevokedError, match="reuse detected"):
            await refresh_svc.rotate(token)


class TestRotationTracksNewTokens:
    async def test_new_tokens_are_tracked_in_store(
        self,
        refresh_svc: RefreshService,
        token_service: TokenService,
        store: MemoryTokenStore,
    ) -> None:
        original = await _create_tracked_refresh(token_service, store, "user-1", "fam-1")
        pair = await refresh_svc.rotate(original)

        # New tokens should be tracked
        new_access_claims = token_service.decode_token(pair.access_token)
        new_refresh_claims = token_service.decode_token(pair.refresh_token)

        # They should exist in the store (not revoked)
        assert await store.is_revoked(new_access_claims["jti"]) is False
        assert await store.is_revoked(new_refresh_claims["jti"]) is False

        # They should be in the same family
        assert await store.get_family_id(new_access_claims["jti"]) == "fam-1"
        assert await store.get_family_id(new_refresh_claims["jti"]) == "fam-1"
