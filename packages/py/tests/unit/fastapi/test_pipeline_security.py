"""Security tests for pipeline routes — logout exception swallowing, auth checks."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import FakeBackend, FakeUser
from urauth.backends.base import UserFunctions
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.exceptions import register_exception_handlers
from urauth.fastapi.router import create_password_auth_router
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.tokens.jwt import TokenService

SECRET = "test-secret-key-32-chars-long-xx"


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key=SECRET)


@pytest.fixture
def store() -> MemoryTokenStore:
    return MemoryTokenStore()


@pytest.fixture
def svc(config: AuthConfig) -> TokenService:
    return TokenService(config)


@pytest.fixture
def app(config: AuthConfig, store: MemoryTokenStore, svc: TokenService) -> FastAPI:
    transport = BearerTransport()
    alice = FakeUser(id="user-1", email="alice@example.com", password_hash="secret123")
    bob = FakeUser(id="user-2", email="bob@example.com", password_hash="pass456")
    backend = FakeBackend([alice, bob])
    user_fns = UserFunctions(
        get_by_id=backend.get_by_id,
        get_by_username=backend.get_by_username,
        verify_password=backend.verify_password,
    )
    app = FastAPI()
    register_exception_handlers(app)
    router = create_password_auth_router(user_fns, svc, store, transport, config)
    app.include_router(router)
    return app


# ── Vuln #1: Logout-all with expired token ────────────────────


class TestLogoutAllExpiredToken:
    """When logout-all is called with an expired token, the endpoint returns 204
    but never calls revoke_all_for_user. This is a logic dead-end where the user
    thinks all sessions are revoked but they aren't.
    """

    async def test_logout_all_expired_token_does_not_revoke(
        self, app: FastAPI, svc: TokenService, store: MemoryTokenStore
    ) -> None:
        """Demonstrate that expired tokens cause logout-all to skip revocation."""
        # Create tokens for user-1
        token1 = svc.create_access_token("user-1")
        token2 = svc.create_access_token("user-1")
        payload1 = svc.validate_access_token(token1)
        payload2 = svc.validate_access_token(token2)
        await store.add_token(payload1.jti, "user-1", "access", payload1.exp)
        await store.add_token(payload2.jti, "user-1", "access", payload2.exp)

        # Create an expired token for the logout-all call
        expired_svc = TokenService(AuthConfig(secret_key=SECRET, access_token_ttl=-1))
        expired_token = expired_svc.create_access_token("user-1")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/logout-all",
                headers={"Authorization": f"Bearer {expired_token}"},
            )
            # Returns 204 — looks successful to the user
            assert resp.status_code == 204

        # BUG: The other tokens are NOT revoked because decode_token raised TokenExpiredError
        # and the except clause returned early without calling revoke_all_for_user.
        # This test documents the current behavior.
        assert await store.is_revoked(payload1.jti) is False
        assert await store.is_revoked(payload2.jti) is False

    async def test_logout_all_with_valid_token_revokes_all(
        self, app: FastAPI, svc: TokenService, store: MemoryTokenStore
    ) -> None:
        """With a valid token, logout-all correctly revokes all tokens for the user."""
        token1 = svc.create_access_token("user-1")
        token2 = svc.create_access_token("user-1")
        payload1 = svc.validate_access_token(token1)
        payload2 = svc.validate_access_token(token2)
        await store.add_token(payload1.jti, "user-1", "access", payload1.exp)
        await store.add_token(payload2.jti, "user-1", "access", payload2.exp)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/logout-all",
                headers={"Authorization": f"Bearer {token1}"},
            )
            assert resp.status_code == 204

        assert await store.is_revoked(payload1.jti) is True
        assert await store.is_revoked(payload2.jti) is True

    async def test_logout_expired_token_still_clears_cookie(
        self, app: FastAPI, svc: TokenService
    ) -> None:
        """Even with expired token, logout should clear the transport (cookie/header)."""
        expired_svc = TokenService(AuthConfig(secret_key=SECRET, access_token_ttl=-1))
        token = expired_svc.create_access_token("user-1")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 204


# ── Vuln #1 (pipeline): Exception swallowing in logout ────────


class TestLogoutExceptionSwallowing:
    """Pipeline route logout uses `except Exception: pass` which hides storage errors."""

    async def test_logout_with_garbage_token_returns_204(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/logout",
                headers={"Authorization": "Bearer not.a.valid.jwt"},
            )
            assert resp.status_code == 204

    async def test_logout_without_token_returns_204(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout")
            assert resp.status_code == 204


# ── Login edge cases ──────────────────────────────────────────


class TestLoginEdgeCases:
    async def test_login_wrong_password(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/login",
                json={"username": "alice@example.com", "password": "wrong"},
            )
            assert resp.status_code == 401

    async def test_login_nonexistent_user(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/login",
                json={"username": "nobody@example.com", "password": "pass"},
            )
            assert resp.status_code == 401

    async def test_login_empty_username(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/login",
                json={"username": "", "password": "pass"},
            )
            assert resp.status_code == 401

    async def test_login_empty_password(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/login",
                json={"username": "alice@example.com", "password": ""},
            )
            assert resp.status_code == 401

    async def test_login_missing_fields(self, app: FastAPI) -> None:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/login", json={})
            assert resp.status_code == 422
