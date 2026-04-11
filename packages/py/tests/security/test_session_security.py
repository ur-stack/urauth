"""Security tests for session and token store behavior.

Validates family revocation isolation, user isolation,
TTL expiry, and basic concurrency safety.
"""

from __future__ import annotations

import asyncio
import time

from urauth.backends.memory import MemorySessionStore, MemoryTokenStore


class TestFamilyRevocation:
    """Revoking a family must revoke all tokens in that family and no others."""

    async def test_family_revocation_revokes_all_in_family(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        # Add 3 tokens in family-A
        await store.add_token("jti-1", "user-1", "access", now + 3600, family_id="family-A")
        await store.add_token("jti-2", "user-1", "refresh", now + 86400, family_id="family-A")
        await store.add_token("jti-3", "user-1", "access", now + 3600, family_id="family-A")

        await store.revoke_family("family-A")

        assert await store.is_revoked("jti-1") is True
        assert await store.is_revoked("jti-2") is True
        assert await store.is_revoked("jti-3") is True

    async def test_family_revocation_does_not_affect_other_families(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        await store.add_token("jti-a1", "user-1", "access", now + 3600, family_id="family-A")
        await store.add_token("jti-b1", "user-1", "access", now + 3600, family_id="family-B")
        await store.add_token("jti-b2", "user-1", "refresh", now + 86400, family_id="family-B")

        await store.revoke_family("family-A")

        assert await store.is_revoked("jti-a1") is True
        assert await store.is_revoked("jti-b1") is False
        assert await store.is_revoked("jti-b2") is False

    async def test_family_revocation_does_not_affect_other_users(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        await store.add_token("jti-u1", "user-1", "access", now + 3600, family_id="family-1")
        await store.add_token("jti-u2", "user-2", "access", now + 3600, family_id="family-2")

        await store.revoke_family("family-1")

        assert await store.is_revoked("jti-u1") is True
        assert await store.is_revoked("jti-u2") is False


class TestRevokeAllForUser:
    """revoke_all_for_user must only affect the targeted user."""

    async def test_revokes_all_tokens_for_target_user(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        await store.add_token("jti-1", "user-1", "access", now + 3600)
        await store.add_token("jti-2", "user-1", "refresh", now + 86400)

        await store.revoke_all_for_user("user-1")

        assert await store.is_revoked("jti-1") is True
        assert await store.is_revoked("jti-2") is True

    async def test_does_not_affect_other_users(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        await store.add_token("jti-u1", "user-1", "access", now + 3600)
        await store.add_token("jti-u2", "user-2", "access", now + 3600)
        await store.add_token("jti-u3", "user-2", "refresh", now + 86400)

        await store.revoke_all_for_user("user-1")

        assert await store.is_revoked("jti-u1") is True
        assert await store.is_revoked("jti-u2") is False
        assert await store.is_revoked("jti-u3") is False


class TestSessionExpiredTTL:
    """Session with expired TTL must return None."""

    async def test_expired_session_returns_none(self) -> None:
        store = MemorySessionStore()
        await store.create("sid-1", "user-1", {"foo": "bar"}, ttl=1)

        # Immediately should be available
        session = await store.get("sid-1")
        assert session is not None

        # Wait for expiry (use a very short TTL and wait)
        store2 = MemorySessionStore()
        await store2.create("sid-2", "user-1", {"foo": "bar"}, ttl=0)
        # TTL=0 means expires_at = time.time() + 0 = now, so any get after
        # should see it as expired (time.time() > expires_at may be false if
        # called in the same tick). We'll manipulate directly.
        store2._sessions["sid-2"]["expires_at"] = time.time() - 1
        session = await store2.get("sid-2")
        assert session is None

    async def test_nonexistent_session_returns_none(self) -> None:
        store = MemorySessionStore()
        assert await store.get("does-not-exist") is None


class TestConcurrentTokenOperations:
    """Basic concurrency test: parallel operations should not corrupt state."""

    async def test_concurrent_add_and_revoke(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        # Add many tokens concurrently
        async def add_token(i: int) -> None:
            await store.add_token(f"jti-{i}", "user-1", "access", now + 3600, family_id="family-A")

        await asyncio.gather(*[add_token(i) for i in range(100)])

        # All should be tracked
        for i in range(100):
            assert await store.is_revoked(f"jti-{i}") is False

        # Revoke the family
        await store.revoke_family("family-A")

        # All should be revoked
        for i in range(100):
            assert await store.is_revoked(f"jti-{i}") is True

    async def test_concurrent_add_tokens_different_users(self) -> None:
        store = MemoryTokenStore()
        now = time.time()

        async def add_for_user(user_id: str, start: int) -> None:
            for i in range(50):
                await store.add_token(f"jti-{user_id}-{start + i}", user_id, "access", now + 3600)

        await asyncio.gather(
            add_for_user("user-1", 0),
            add_for_user("user-2", 0),
        )

        # Revoke user-1 only
        await store.revoke_all_for_user("user-1")

        for i in range(50):
            assert await store.is_revoked(f"jti-user-1-{i}") is True
            assert await store.is_revoked(f"jti-user-2-{i}") is False
