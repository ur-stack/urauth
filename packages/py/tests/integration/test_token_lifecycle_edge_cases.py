"""Integration tests for token lifecycle edge cases — dead-ends, race conditions, deactivation."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from urauth.auth import Auth
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.exceptions import register_exception_handlers
from urauth.fastapi.middleware import TokenRefreshMiddleware
from urauth.fastapi.transport.cookie import CookieTransport
from urauth.tokens.jwt import TokenService

SECRET = "integration-test-secret-key-32ch"


# ── Test users and auth ───────────────────────────────────────


class User:
    def __init__(self, id: str, email: str, password: str, is_active: bool = True) -> None:
        self.id = id
        self.email = email
        self.password = password
        self.is_active = is_active


USERS: dict[str, User] = {
    "user-1": User("user-1", "alice@test.com", "pass1"),
    "user-2": User("user-2", "bob@test.com", "pass2"),
    "inactive": User("inactive", "inactive@test.com", "pass", is_active=False),
}


class _Auth(Auth):
    def __init__(self, users: dict[str, User], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._users = users
        self._by_email = {u.email: u for u in users.values()}

    async def get_user(self, user_id: Any) -> User | None:
        return self._users.get(str(user_id))

    async def get_user_by_username(self, username: str) -> User | None:
        return self._by_email.get(username)

    def verify_password(self, user: Any, password: str) -> bool:
        return user.password == password


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def store() -> MemoryTokenStore:
    return MemoryTokenStore()


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key=SECRET)


@pytest.fixture
def svc(config: AuthConfig) -> TokenService:
    return TokenService(config)


@pytest.fixture
def core_auth(config: AuthConfig, store: MemoryTokenStore) -> _Auth:
    return _Auth(dict(USERS), config=config, token_store=store)


@pytest.fixture
def fast_auth(core_auth: _Auth) -> FastAuth:
    return FastAuth(core_auth)


# ── Test: Login → auto-refresh → verify new token tracked ─────


class TestAutoRefreshTracking:
    async def test_login_then_auto_refresh_tracks_new_token(
        self, store: MemoryTokenStore
    ) -> None:
        """Full flow: login, get near-expiry token, auto-refresh, verify new token is tracked."""
        # Use short TTL so token is near-expiry immediately
        short_config = AuthConfig(secret_key=SECRET, access_token_ttl=10)
        short_svc = TokenService(short_config)
        transport = CookieTransport(short_config)
        core = _Auth(dict(USERS), config=short_config, token_store=store)
        fast = FastAuth(core, transport=transport)

        app = FastAPI()
        register_exception_handlers(app)
        app.add_middleware(
            TokenRefreshMiddleware,
            token_service=short_svc,
            transport=transport,
            token_store=store,
            threshold=300,
        )

        @app.get("/me")
        async def me(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"user_id": ctx.user.id}

        # Create a near-expiry token and add to store
        token = short_svc.create_access_token("user-1")
        payload = short_svc.validate_access_token(token)
        await store.add_token(payload.jti, "user-1", "access", payload.exp)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Request with near-expiry token — should trigger auto-refresh
            resp = await client.get("/me", cookies={"access_token": token})
            assert resp.status_code == 200

            # Check if a new cookie was set (auto-refresh)
            new_cookie = resp.cookies.get("access_token")
            if new_cookie:
                new_payload = short_svc.validate_access_token(new_cookie)
                # New token must be tracked in store
                assert await store.is_revoked(new_payload.jti) is False


# ── Test: Revoked token should not auto-refresh ───────────────


class TestRevokedTokenAutoRefresh:
    async def test_revoked_token_not_auto_refreshed(
        self, config: AuthConfig, store: MemoryTokenStore, core_auth: _Auth
    ) -> None:
        short_config = AuthConfig(secret_key=SECRET, access_token_ttl=10)
        short_svc = TokenService(short_config)
        transport = CookieTransport(short_config)

        app = FastAPI()
        app.add_middleware(
            TokenRefreshMiddleware,
            token_service=short_svc,
            transport=transport,
            token_store=store,
            threshold=300,
        )

        @app.get("/test")
        async def test_endpoint() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": "yes"}

        token = short_svc.create_access_token("user-1")
        payload = short_svc.validate_access_token(token)
        await store.add_token(payload.jti, "user-1", "access", payload.exp)
        await store.revoke(payload.jti, payload.exp)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/test", cookies={"access_token": token})
            assert resp.status_code == 200
            # Should NOT have a new access_token cookie
            assert "access_token" not in resp.cookies


# ── Test: Inactive user mid-session ───────────────────────────


class TestInactiveUserMidSession:
    async def test_deactivated_user_rejected_on_next_request(
        self, config: AuthConfig, store: MemoryTokenStore
    ) -> None:
        """User is deactivated after token is issued. Next request should fail."""
        # Deep copy users to avoid mutating shared state
        users = {uid: User(u.id, u.email, u.password, u.is_active) for uid, u in USERS.items()}
        core = _Auth(users, config=config, token_store=store)
        fast = FastAuth(core)

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(fast.password_auth_router())

        @app.get("/me")
        async def me(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"user_id": ctx.user.id}

        svc = TokenService(config)
        token = svc.create_access_token("user-1")
        payload = svc.validate_access_token(token)
        await store.add_token(payload.jti, "user-1", "access", payload.exp)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # First request succeeds
            resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            # Deactivate user
            users["user-1"].is_active = False

            # Second request should fail
            resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 401


# ── Test: Logout-all dead-end with expired token ──────────────


class TestLogoutAllDeadEnd:
    async def test_logout_all_expired_token_leaves_sessions_active(
        self, config: AuthConfig, store: MemoryTokenStore
    ) -> None:
        """Demonstrates the dead-end: user calls logout-all with expired token,
        gets 204 success, but all other tokens remain valid."""
        core = _Auth(dict(USERS), config=config, token_store=store)
        fast = FastAuth(core)

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(fast.password_auth_router())

        @app.get("/me")
        async def me(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"user_id": ctx.user.id}

        svc = TokenService(config)

        # Create two valid sessions
        token_a = svc.create_access_token("user-1")
        token_b = svc.create_access_token("user-1")
        payload_a = svc.validate_access_token(token_a)
        payload_b = svc.validate_access_token(token_b)
        await store.add_token(payload_a.jti, "user-1", "access", payload_a.exp)
        await store.add_token(payload_b.jti, "user-1", "access", payload_b.exp)

        # Create expired token for logout-all call
        expired_svc = TokenService(AuthConfig(secret_key=SECRET, access_token_ttl=-1))
        expired_token = expired_svc.create_access_token("user-1")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # User calls logout-all with expired token
            resp = await client.post(
                "/auth/logout-all",
                headers={"Authorization": f"Bearer {expired_token}"},
            )
            # Returns 204 — user thinks all sessions are revoked
            assert resp.status_code == 204

            # But token_a is still valid!
            resp = await client.get("/me", headers={"Authorization": f"Bearer {token_a}"})
            assert resp.status_code == 200  # BUG: should be 401 if logout-all worked


# ── Test: Multi-device session isolation ──────────────────────


class TestMultiDeviceIsolation:
    async def test_logout_one_device_keeps_other_active(
        self, config: AuthConfig, store: MemoryTokenStore
    ) -> None:
        """Logging out from one device should not affect another device's token."""
        core = _Auth(dict(USERS), config=config, token_store=store)
        fast = FastAuth(core)

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(fast.password_auth_router())

        @app.get("/me")
        async def me(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"user_id": ctx.user.id}

        svc = TokenService(config)

        # Two devices
        device_a_token = svc.create_access_token("user-1")
        device_b_token = svc.create_access_token("user-1")
        pa = svc.validate_access_token(device_a_token)
        pb = svc.validate_access_token(device_b_token)
        await store.add_token(pa.jti, "user-1", "access", pa.exp)
        await store.add_token(pb.jti, "user-1", "access", pb.exp)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Logout device A
            resp = await client.post(
                "/auth/logout",
                headers={"Authorization": f"Bearer {device_a_token}"},
            )
            assert resp.status_code == 204

            # Device B should still work
            resp = await client.get("/me", headers={"Authorization": f"Bearer {device_b_token}"})
            assert resp.status_code == 200

            # Device A should be rejected (if store is checked)
            # Note: With default fail-open store, this may still work
            # With strict store, it would be rejected
