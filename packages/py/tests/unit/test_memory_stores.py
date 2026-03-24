"""Tests for MemoryTokenStore and MemorySessionStore — edge cases and correctness."""

from __future__ import annotations

import time

import pytest

from urauth.backends.memory import MemorySessionStore, MemoryTokenStore


class TestMemoryTokenStore:
    @pytest.fixture
    def store(self) -> MemoryTokenStore:
        return MemoryTokenStore()

    async def test_unknown_jti_is_not_revoked(self, store: MemoryTokenStore) -> None:
        """Tokens not tracked are considered valid (not revoked)."""
        assert await store.is_revoked("nonexistent-jti") is False

    async def test_revoke_unknown_jti_is_noop(self, store: MemoryTokenStore) -> None:
        """Revoking an unknown JTI should not raise."""
        await store.revoke("nonexistent-jti", time.time() + 3600)
        # Should still not appear as revoked since it was never tracked
        assert await store.is_revoked("nonexistent-jti") is False

    async def test_add_and_revoke(self, store: MemoryTokenStore) -> None:
        await store.add_token(jti="t1", user_id="u1", token_type="access", expires_at=time.time() + 3600)
        assert await store.is_revoked("t1") is False
        await store.revoke("t1", time.time() + 3600)
        assert await store.is_revoked("t1") is True

    async def test_revoke_all_for_user(self, store: MemoryTokenStore) -> None:
        await store.add_token(jti="t1", user_id="u1", token_type="access", expires_at=time.time() + 3600)
        await store.add_token(jti="t2", user_id="u1", token_type="refresh", expires_at=time.time() + 3600)
        await store.add_token(jti="t3", user_id="u2", token_type="access", expires_at=time.time() + 3600)

        await store.revoke_all_for_user("u1")

        assert await store.is_revoked("t1") is True
        assert await store.is_revoked("t2") is True
        assert await store.is_revoked("t3") is False  # different user

    async def test_revoke_all_for_user_with_no_tokens(self, store: MemoryTokenStore) -> None:
        """No-op when user has no tokens."""
        await store.revoke_all_for_user("unknown-user")  # should not raise

    async def test_revoke_family(self, store: MemoryTokenStore) -> None:
        await store.add_token(
            jti="t1", user_id="u1", token_type="access", expires_at=time.time() + 3600, family_id="fam-a"
        )
        await store.add_token(
            jti="t2", user_id="u1", token_type="refresh", expires_at=time.time() + 3600, family_id="fam-a"
        )
        await store.add_token(
            jti="t3", user_id="u1", token_type="access", expires_at=time.time() + 3600, family_id="fam-b"
        )

        await store.revoke_family("fam-a")

        assert await store.is_revoked("t1") is True
        assert await store.is_revoked("t2") is True
        assert await store.is_revoked("t3") is False  # different family

    async def test_get_family_id(self, store: MemoryTokenStore) -> None:
        await store.add_token(
            jti="t1", user_id="u1", token_type="refresh", expires_at=time.time() + 3600, family_id="fam-1"
        )
        assert await store.get_family_id("t1") == "fam-1"

    async def test_get_family_id_unknown(self, store: MemoryTokenStore) -> None:
        assert await store.get_family_id("nonexistent") is None

    async def test_get_sessions_returns_active_only(self, store: MemoryTokenStore) -> None:
        now = time.time()
        # Active session
        await store.add_token(
            jti="t1",
            user_id="u1",
            token_type="access",
            expires_at=now + 3600,
            family_id="fam-active",
            metadata={"ip": "1.2.3.4"},
        )
        # Expired session
        await store.add_token(
            jti="t2", user_id="u1", token_type="access", expires_at=now - 1, family_id="fam-expired"
        )
        # Revoked session
        await store.add_token(
            jti="t3", user_id="u1", token_type="access", expires_at=now + 3600, family_id="fam-revoked"
        )
        await store.revoke("t3", now + 3600)

        sessions = await store.get_sessions("u1")
        family_ids = [s["family_id"] for s in sessions]
        assert "fam-active" in family_ids
        assert "fam-expired" not in family_ids
        assert "fam-revoked" not in family_ids

    async def test_get_sessions_unknown_user(self, store: MemoryTokenStore) -> None:
        assert await store.get_sessions("nobody") == []

    async def test_family_metadata(self, store: MemoryTokenStore) -> None:
        meta = {"ip": "10.0.0.1", "user_agent": "TestAgent"}
        await store.add_token(
            jti="t1",
            user_id="u1",
            token_type="access",
            expires_at=time.time() + 3600,
            family_id="fam-1",
            metadata=meta,
        )
        sessions = await store.get_sessions("u1")
        assert len(sessions) == 1
        assert sessions[0]["metadata"]["ip"] == "10.0.0.1"
        assert sessions[0]["metadata"]["user_agent"] == "TestAgent"

    async def test_family_metadata_updated_on_second_add(self, store: MemoryTokenStore) -> None:
        await store.add_token(
            jti="t1",
            user_id="u1",
            token_type="access",
            expires_at=time.time() + 3600,
            family_id="fam-1",
            metadata={"ip": "1.1.1.1"},
        )
        await store.add_token(
            jti="t2",
            user_id="u1",
            token_type="refresh",
            expires_at=time.time() + 3600,
            family_id="fam-1",
            metadata={"device": "mobile"},
        )
        sessions = await store.get_sessions("u1")
        assert sessions[0]["metadata"]["ip"] == "1.1.1.1"
        assert sessions[0]["metadata"]["device"] == "mobile"


class TestMemorySessionStore:
    @pytest.fixture
    def store(self) -> MemorySessionStore:
        return MemorySessionStore()

    async def test_create_and_get(self, store: MemorySessionStore) -> None:
        await store.create("s1", "u1", {"role": "admin"}, ttl=3600)
        session = await store.get("s1")
        assert session is not None
        assert session["user_id"] == "u1"
        assert session["data"]["role"] == "admin"

    async def test_get_nonexistent(self, store: MemorySessionStore) -> None:
        assert await store.get("nonexistent") is None

    async def test_expired_session_returns_none(self, store: MemorySessionStore) -> None:
        await store.create("s1", "u1", {}, ttl=-1)  # already expired
        assert await store.get("s1") is None

    async def test_delete_session(self, store: MemorySessionStore) -> None:
        await store.create("s1", "u1", {}, ttl=3600)
        await store.delete("s1")
        assert await store.get("s1") is None

    async def test_delete_nonexistent_is_noop(self, store: MemorySessionStore) -> None:
        await store.delete("nonexistent")  # should not raise

    async def test_delete_all_for_user(self, store: MemorySessionStore) -> None:
        await store.create("s1", "u1", {}, ttl=3600)
        await store.create("s2", "u1", {}, ttl=3600)
        await store.create("s3", "u2", {}, ttl=3600)

        await store.delete_all_for_user("u1")

        assert await store.get("s1") is None
        assert await store.get("s2") is None
        assert await store.get("s3") is not None  # different user

    async def test_delete_all_for_user_with_no_sessions(self, store: MemorySessionStore) -> None:
        await store.delete_all_for_user("nobody")  # should not raise
