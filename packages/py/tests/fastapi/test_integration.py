"""Integration tests — full FastAPI app with password auth flow."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import FakeBackend, FakeUser
from urauth import AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAPIAuth


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
    auth = FastAPIAuth(backend, config, token_store=token_store)

    app = FastAPI(lifespan=auth.lifespan())
    auth.init_app(app)
    app.include_router(auth.password_auth_router())

    @app.get("/me")
    async def me(user=auth.current_user()):
        return {"id": user.id, "email": user.email}

    @app.get("/admin")
    async def admin(user=auth.current_user(roles=["admin"])):
        return {"id": user.id, "admin": True}

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
        # Login first
        login_resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "secret123",
            },
        )
        token = login_resp.json()["access_token"]

        # Access protected route
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

        # Logout
        resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 204

        # Token should be revoked
        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401


class TestSubclassApproach:
    """Approach A: subclass FastAPIAuth and override methods."""

    @pytest.fixture
    def app(self, alice: FakeUser, bob: FakeUser) -> FastAPI:
        users_by_id = {u.id: u for u in [alice, bob]}
        users_by_email = {u.email: u for u in [alice, bob]}

        class MyAuth(FastAPIAuth):
            async def get_user(self, user_id: str) -> FakeUser | None:
                return users_by_id.get(user_id)

            async def get_user_by_username(self, username: str) -> FakeUser | None:
                return users_by_email.get(username)

            async def verify_password(self, user: FakeUser, password: str) -> bool:
                return user.password_hash == password

        config = AuthConfig(secret_key="subclass-test-key")
        token_store = MemoryTokenStore()
        auth = MyAuth(config=config, token_store=token_store)

        app = FastAPI(lifespan=auth.lifespan())
        auth.init_app(app)
        app.include_router(auth.password_auth_router())

        @app.get("/me")
        async def me(user=auth.current_user()):
            return {"id": user.id, "email": user.email}

        return app

    @pytest.fixture
    async def client(self, app: FastAPI) -> AsyncGenerator[AsyncClient]:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_login_and_me(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={"username": "alice@example.com", "password": "secret123"},
        )
        assert resp.status_code == 200
        token = resp.json()["access_token"]

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_wrong_password(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={"username": "alice@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401


class TestCallableApproach:
    """Approach B: pass callables directly."""

    @pytest.fixture
    def app(self, alice: FakeUser, bob: FakeUser) -> FastAPI:
        backend = FakeBackend([alice, bob])
        config = AuthConfig(secret_key="callable-test-key")
        token_store = MemoryTokenStore()
        auth = FastAPIAuth(
            config=config,
            get_user=backend.get_by_id,
            get_user_by_username=backend.get_by_username,
            verify_password=backend.verify_password,
            token_store=token_store,
        )

        app = FastAPI(lifespan=auth.lifespan())
        auth.init_app(app)
        app.include_router(auth.password_auth_router())

        @app.get("/me")
        async def me(user=auth.current_user()):
            return {"id": user.id, "email": user.email}

        return app

    @pytest.fixture
    async def client(self, app: FastAPI) -> AsyncGenerator[AsyncClient]:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_login_and_me(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={"username": "alice@example.com", "password": "secret123"},
        )
        assert resp.status_code == 200
        token = resp.json()["access_token"]

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_wrong_password(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/login",
            json={"username": "alice@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401


class TestRBAC:
    @pytest.mark.asyncio
    async def test_admin_allowed(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={
                "username": "alice@example.com",
                "password": "secret123",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_viewer_denied_admin(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={
                "username": "bob@example.com",
                "password": "password456",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
