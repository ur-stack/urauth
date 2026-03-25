"""Security tests for auth router endpoints — graceful degradation and session metadata."""

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
from urauth.tokens.lifecycle import TokenLifecycle

SECRET = "test-secret-key-32-chars-long-xx"

_Setup = tuple[FastAPI, TokenService, MemoryTokenStore]


@pytest.fixture
def setup() -> _Setup:
    config = AuthConfig(secret_key=SECRET)
    store = MemoryTokenStore()
    transport = BearerTransport()
    token_svc = TokenService(config)
    alice = FakeUser(id="user-1", email="alice@example.com", password_hash="secret123")
    backend = FakeBackend([alice])
    user_fns = UserFunctions(
        get_by_id=backend.get_by_id,
        get_by_username=backend.get_by_username,
        verify_password=backend.verify_password,
    )

    app = FastAPI()
    register_exception_handlers(app)
    lifecycle = TokenLifecycle(config, store)
    router = create_password_auth_router(user_fns, lifecycle, transport, config)
    app.include_router(router)
    return app, token_svc, store


class TestLogoutEdgeCases:
    async def test_logout_with_expired_token_returns_204(self, setup: _Setup) -> None:
        app, _, _ = setup
        expired_svc = TokenService(AuthConfig(secret_key=SECRET, access_token_ttl=-1))
        token = expired_svc.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 204

    async def test_logout_without_token_returns_204(self, setup: _Setup) -> None:
        app, _, _ = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout")
            assert resp.status_code == 204

    async def test_logout_all_without_token_returns_204(self, setup: _Setup) -> None:
        app, _, _ = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout-all")
            assert resp.status_code == 204

    async def test_logout_with_garbage_token_returns_204(self, setup: _Setup) -> None:
        app, _, _ = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/auth/logout", headers={"Authorization": "Bearer garbage.token.here"})
            assert resp.status_code == 204


class TestSessionMetadata:
    async def test_login_stores_session_metadata(self, setup: _Setup) -> None:
        app, _, store = setup
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/auth/login",
                json={"username": "alice@example.com", "password": "secret123"},
                headers={"User-Agent": "TestBrowser/1.0"},
            )
            assert resp.status_code == 200

        sessions = await store.get_sessions("user-1")
        assert len(sessions) >= 1
        meta = sessions[0].get("metadata", {})
        assert "ip" in meta or "user_agent" in meta
