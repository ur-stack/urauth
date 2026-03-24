"""Integration tests — full FastAPI app with password auth flow."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import FakeBackend, FakeUser
from urauth import Auth, AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.context import AuthContext
from urauth.fastapi import FastAuth


class _BackendAuth(Auth):
    """Auth subclass backed by FakeBackend for testing."""

    def __init__(self, backend: FakeBackend, **kwargs: Any) -> None:
        super().__init__(**kwargs)  # pyright: ignore[reportUnknownArgumentType]
        self._backend = backend

    async def get_user(self, user_id: Any) -> Any:
        return await self._backend.get_by_id(str(user_id))

    async def get_user_by_username(self, username: str) -> Any:
        return await self._backend.get_by_username(username)

    async def verify_password(self, user: Any, password: str) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        return await self._backend.verify_password(user, password)


@pytest.fixture
def alice() -> FakeUser:
    return FakeUser(
        id="user-1",
        email="alice@example.com",
        roles=["admin"],
        password_hash="secret123",
    )


@pytest.fixture
def bob() -> FakeUser:
    return FakeUser(
        id="user-2",
        email="bob@example.com",
        roles=["viewer"],
        password_hash="password456",
    )


@pytest.fixture
def app(alice: FakeUser, bob: FakeUser) -> FastAPI:
    backend = FakeBackend([alice, bob])
    config = AuthConfig(secret_key="integration-test-key")
    token_store = MemoryTokenStore()
    core = _BackendAuth(backend, config=config, token_store=token_store)
    auth = FastAuth(core)

    app = FastAPI(lifespan=auth.lifespan())
    auth.init_app(app)
    app.include_router(auth.password_auth_router())

    @app.get("/me")
    async def me(ctx: AuthContext = Depends(auth.context)):  # pyright: ignore[reportUnusedFunction]
        return {"id": ctx.user.id, "email": ctx.user.email}

    @app.get("/admin")
    @auth.require(auth._auth.get_user_roles)  # type: ignore[arg-type]  # We use a simple role check instead
    async def admin(ctx: AuthContext = Depends(auth.context)):  # pyright: ignore[reportUnusedFunction]
        return {"id": ctx.user.id, "admin": True}

    return app


@pytest.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestPasswordAuthFlow:
    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "secret123",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "wrong",
            },
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_unknown_user(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={
                "username": "nobody@example.com",
                "password": "x",
            },
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_route(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "secret123",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_no_token_401(self, client: AsyncClient) -> None:
        resp = await client.get("/me")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_token(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "secret123",
            },
        )
        refresh_token = login_resp.json()["refresh_token"]

        resp = await client.post(
            "/auth/refresh",
            json={
                "refresh_token": refresh_token,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["access_token"] != login_resp.json()["access_token"]

    @pytest.mark.asyncio
    async def test_logout_revokes_token(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "secret123",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 204

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
