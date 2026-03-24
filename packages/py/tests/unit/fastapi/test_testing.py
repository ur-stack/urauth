"""Tests for testing utilities."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import FakeBackend, FakeUser
from urauth import Auth, AuthConfig
from urauth.context import AuthContext
from urauth.fastapi import FastAuth
from urauth.fastapi.exceptions import register_exception_handlers
from urauth.fastapi.testing import create_test_token


class _BackendAuth(Auth):
    def __init__(self, backend: FakeBackend, **kwargs: Any) -> None:
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownArgumentType]
        self._backend = backend

    async def get_user(self, user_id: Any) -> Any:
        return await self._backend.get_by_id(str(user_id))

    async def get_user_by_username(self, username: str) -> Any:
        return await self._backend.get_by_username(username)

    async def verify_password(self, user: Any, password: str) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        return await self._backend.verify_password(user, password)


class TestCreateTestToken:
    def test_creates_valid_pair(self) -> None:
        pair = create_test_token(user_id="u1", roles=["admin"])
        assert pair.access_token
        assert pair.refresh_token
        assert pair.token_type == "bearer"


class TestCurrentUserDependency:
    @pytest.mark.asyncio
    async def test_current_user_returns_user(self) -> None:
        alice = FakeUser(id="user-1", email="alice@example.com", roles=["admin"])
        backend = FakeBackend([alice])
        config = AuthConfig(secret_key="test-key")
        core = _BackendAuth(backend, config=config)
        auth = FastAuth(core)

        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/me")
        async def me(ctx: AuthContext = Depends(auth.context)):  # pyright: ignore[reportUnusedFunction]
            if not ctx.is_authenticated():
                from urauth.exceptions import UnauthorizedError

                raise UnauthorizedError()
            return {"id": ctx.user.id, "email": ctx.user.email}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Without token: should fail
            resp = await client.get("/me")
            assert resp.status_code == 401

            # With token: should succeed
            pair = auth.token_service.create_token_pair("user-1", roles=["admin"])
            resp = await client.get("/me", headers={"Authorization": f"Bearer {pair.access_token}"})
            assert resp.status_code == 200
            assert resp.json()["email"] == "alice@example.com"
