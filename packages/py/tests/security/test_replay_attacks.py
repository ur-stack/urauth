"""Security tests for token replay attack scenarios.

Validates stateless JWT limitations, store-based revocation detection,
refresh token rotation family tracking, and cross-user replay prevention.
"""

from __future__ import annotations

import pytest

from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.exceptions import TokenRevokedError, UnauthorizedError
from urauth.tokens.jwt import TokenService
from urauth.tokens.lifecycle import IssueRequest, TokenLifecycle


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(
        secret_key="test-secret-key-32-chars-long-xx",
        environment="testing",
    )


@pytest.fixture
def store() -> MemoryTokenStore:
    return MemoryTokenStore(strict=True)


@pytest.fixture
def lifecycle(config: AuthConfig, store: MemoryTokenStore) -> TokenLifecycle:
    return TokenLifecycle(config=config, token_store=store)


@pytest.fixture
def svc(config: AuthConfig) -> TokenService:
    return TokenService(config)


class TestAccessTokenStatelessLimitation:
    """Access tokens are stateless JWTs -- revocation requires store check.

    This documents the inherent limitation: a revoked access token still
    has a valid JWT signature. Only the store-aware validate() method
    catches revocation.
    """

    async def test_revoked_access_token_still_valid_jwt(self, lifecycle: TokenLifecycle, svc: TokenService) -> None:
        """JWT signature remains valid after revocation -- this is expected for stateless tokens."""
        issued = await lifecycle.issue(IssueRequest(user_id="user-1"))

        # Revoke via lifecycle
        await lifecycle.revoke_all("user-1")

        # Raw JWT decode still works (stateless validation)
        payload = svc.validate_access_token(issued.access_token)
        assert payload.sub == "user-1"

    async def test_revoked_access_token_detected_by_lifecycle_validate(self, lifecycle: TokenLifecycle) -> None:
        """The lifecycle.validate() method checks the store and catches revocation."""
        issued = await lifecycle.issue(IssueRequest(user_id="user-1"))

        await lifecycle.revoke_all("user-1")

        with pytest.raises(UnauthorizedError, match="revoked"):
            await lifecycle.validate(issued.access_token)


class TestRefreshTokenRotationFamilyTracking:
    """Refresh token rotation must maintain family lineage."""

    async def test_rotation_produces_same_family(self, lifecycle: TokenLifecycle) -> None:
        issued = await lifecycle.issue(IssueRequest(user_id="user-1"))
        original_family = issued.family_id

        rotated = await lifecycle.refresh(issued.refresh_token)
        assert rotated.family_id == original_family

    async def test_multiple_rapid_rotations_maintain_family(self, lifecycle: TokenLifecycle) -> None:
        issued = await lifecycle.issue(IssueRequest(user_id="user-1"))
        original_family = issued.family_id

        current = issued
        for _ in range(5):
            rotated = await lifecycle.refresh(current.refresh_token)
            assert rotated.family_id == original_family
            current = rotated

    async def test_multiple_rotations_all_succeed(self, lifecycle: TokenLifecycle) -> None:
        issued = await lifecycle.issue(IssueRequest(user_id="user-1"))

        current = issued
        tokens_seen: set[str] = set()
        for _ in range(10):
            rotated = await lifecycle.refresh(current.refresh_token)
            assert rotated.access_token not in tokens_seen
            assert rotated.refresh_token not in tokens_seen
            tokens_seen.add(rotated.access_token)
            tokens_seen.add(rotated.refresh_token)
            current = rotated

    async def test_old_refresh_token_triggers_reuse_detection(self, lifecycle: TokenLifecycle) -> None:
        """Using an already-rotated refresh token triggers reuse detection and family revocation."""
        issued = await lifecycle.issue(IssueRequest(user_id="user-1"))
        old_refresh = issued.refresh_token

        # Rotate once (consuming the old refresh token)
        rotated = await lifecycle.refresh(old_refresh)

        # Attempt to reuse the old refresh token -- should trigger reuse detection
        with pytest.raises(TokenRevokedError, match="reuse"):
            await lifecycle.refresh(old_refresh)

        # The new tokens from rotation should also be revoked (family revocation)
        with pytest.raises((TokenRevokedError, UnauthorizedError)):
            await lifecycle.validate(rotated.access_token)


class TestCrossUserReplayPrevention:
    """Tokens from one user must not be usable for another user's operations."""

    async def test_refresh_token_bound_to_original_user(self, lifecycle: TokenLifecycle) -> None:
        """A refresh token issued to user-1 should produce tokens for user-1, not user-2."""
        user1_issued = await lifecycle.issue(IssueRequest(user_id="user-1"))
        await lifecycle.issue(IssueRequest(user_id="user-2"))

        # Rotate user-1's refresh token
        rotated = await lifecycle.refresh(user1_issued.refresh_token)

        # Validate the new access token -- should be for user-1
        payload = await lifecycle.validate(rotated.access_token)
        assert payload.sub == "user-1"

    async def test_revoke_all_for_user_does_not_affect_other_user(
        self, lifecycle: TokenLifecycle
    ) -> None:
        user1_issued = await lifecycle.issue(IssueRequest(user_id="user-1"))
        user2_issued = await lifecycle.issue(IssueRequest(user_id="user-2"))

        await lifecycle.revoke_all("user-1")

        # user-1 tokens revoked
        with pytest.raises(UnauthorizedError):
            await lifecycle.validate(user1_issued.access_token)

        # user-2 tokens still valid
        payload = await lifecycle.validate(user2_issued.access_token)
        assert payload.sub == "user-2"

    async def test_family_revocation_isolated_between_users(self, lifecycle: TokenLifecycle) -> None:
        user1_issued = await lifecycle.issue(IssueRequest(user_id="user-1"))
        user2_issued = await lifecycle.issue(IssueRequest(user_id="user-2"))

        # Revoke user-1's session family
        await lifecycle.revoke(user1_issued.access_token)

        # user-1's token should be revoked
        with pytest.raises(UnauthorizedError):
            await lifecycle.validate(user1_issued.access_token)

        # user-2 unaffected
        payload = await lifecycle.validate(user2_issued.access_token)
        assert payload.sub == "user-2"


class TestStrictModeUnknownTokens:
    """In strict mode, unknown JTIs should be treated as revoked."""

    async def test_unknown_jti_is_revoked_in_strict_mode(self) -> None:
        store = MemoryTokenStore(strict=True)
        assert await store.is_revoked("never-seen-before") is True

    async def test_unknown_jti_is_not_revoked_in_non_strict_mode(self) -> None:
        store = MemoryTokenStore(strict=False)
        assert await store.is_revoked("never-seen-before") is False
