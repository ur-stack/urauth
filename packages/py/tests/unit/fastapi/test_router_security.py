"""Security tests for auth router endpoints — graceful degradation and session metadata."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import FakeBackend, FakeUser
from urauth.auth import Auth
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.exceptions import register_exception_handlers
from urauth.tokens.jwt import TokenService

SECRET = "test-secret-key-32-chars-long-xx"

_Setup = tuple[FastAPI, TokenService, MemoryTokenStore]


@pytest.fixture
def setup() -> _Setup:
    config = AuthConfig(secret_key=SECRET)
    store = MemoryTokenStore()
    token_svc = TokenService(config)
    alice = FakeUser(id="user-1", email="alice@example.com", password_hash="secret123")
    backend = FakeBackend([alice])

    core = Auth(
        config=config,
        token_store=store,
        get_user=backend.get_by_id,
        get_user_by_username=backend.get_by_username,
        verify_password=backend.verify_password,
    )
    fast = FastAuth(core)

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(fast.password_auth_router())
    return app, token_svc, store


class TestLogoutEdgeCases:
    async def test_logout_with_expired_token_returns_200(self, setup: _Setup) -> None:
        app, _, _ = setup
        expired_svc = TokenService(AuthConfig(secret_key=SECRET, access_token_ttl=-1))
        token = expired_svc.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    async def test_logout_without_token_returns_200(self, setup: _Setup) -> None:
        app, _, _ = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout")
            assert resp.status_code == 200

    async def test_logout_all_without_token_returns_200(self, setup: _Setup) -> None:
        app, _, _ = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout-all")
            assert resp.status_code == 200

    async def test_logout_with_garbage_token_returns_200(self, setup: _Setup) -> None:
        app, _, _ = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout", headers={"Authorization": "Bearer garbage.token.here"})
            assert resp.status_code == 200


class TestSessionMetadata:
    async def test_login_stores_session_metadata(self, setup: _Setup) -> None:
        app, _, store = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/login",
                json={"identifier": "alice@example.com", "password": "secret123"},
                headers={"User-Agent": "TestBrowser/1.0"},
            )
            assert resp.status_code == 200

        sessions = await store.get_sessions("user-1")
        assert len(sessions) >= 1
