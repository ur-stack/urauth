"""Tests for guard edge cases — RequirementGuard, RelationGuard, PolicyGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from urauth.auth import Auth
from urauth.authz.primitives import Action, Permission, Relation, Resource, Role
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.exceptions import register_exception_handlers

SECRET = "test-secret-key-32-chars-long-xx"

read = Action("read")
write = Action("write")
user_res = Resource("user")
post_res = Resource("post")
can_read = Permission(user_res, read)
can_write = Permission(post_res, write)
owns_post = Relation("owner", post_res)
admin_role = Role("admin", [can_read, can_write])
viewer_role = Role("viewer", [can_read])


@dataclass
class FakeUser:
    id: str = "user-1"
    is_active: bool = True
    roles: list[str] = field(default_factory=lambda: ["admin"])


class _GuardTestAuth(Auth):
    def __init__(self, users: dict[str, FakeUser], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._users = users

    async def get_user(self, user_id: Any) -> Any | None:
        return self._users.get(str(user_id))

    async def get_user_by_username(self, username: str) -> Any | None:
        return None

    def verify_password(self, user: Any, password: str) -> bool:
        return False

    def get_user_roles(self, user: Any) -> list[Role]:
        return [admin_role] if "admin" in user.roles else [viewer_role]

    def get_user_relations(self, user: Any) -> list[tuple[Relation, str]]:
        return [(owns_post, "42")]

    def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:
        return relation == owns_post and resource_id == "42"


@pytest.fixture
def admin_user() -> FakeUser:
    return FakeUser(id="user-1", roles=["admin"])


@pytest.fixture
def viewer_user() -> FakeUser:
    return FakeUser(id="user-2", roles=["viewer"])


@pytest.fixture
def auth_setup(admin_user: FakeUser, viewer_user: FakeUser) -> tuple[FastAuth, Auth]:
    config = AuthConfig(secret_key=SECRET)
    store = MemoryTokenStore()
    users = {admin_user.id: admin_user, viewer_user.id: viewer_user}
    core = _GuardTestAuth(users, config=config, token_store=store)
    fast = FastAuth(core)
    return fast, core


class TestRequirementGuard:
    async def test_authorized_user_passes(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/protected")
        @fast.require(can_read)
        async def endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"user": ctx.user.id}

        token = core.token_service.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    async def test_unauthorized_user_gets_403(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/admin-only")
        @fast.require(can_write)
        async def endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"user": ctx.user.id}

        token = core.token_service.create_access_token("user-2")  # viewer
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_no_token_gets_401(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, _ = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/protected")
        @fast.require(can_read)
        async def endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"user": ctx.user.id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected")
            assert resp.status_code == 401

    async def test_depends_mode(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/protected", dependencies=[Depends(fast.require(can_read))])
        async def endpoint() -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"ok": "true"}

        token = core.token_service.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200


class TestRelationGuard:
    async def test_relation_guard_passes_for_owner(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/posts/{post_id}")
        @fast.require_relation(owns_post, resource_id_from="post_id")
        async def endpoint(post_id: str, ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"post": post_id}

        token = core.token_service.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/posts/42", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    async def test_relation_guard_rejects_non_owner(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/posts/{post_id}")
        @fast.require_relation(owns_post, resource_id_from="post_id")
        async def endpoint(post_id: str, ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"post": post_id}

        token = core.token_service.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # User owns post 42, not post 99
            resp = await client.get("/posts/99", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403


class TestPolicyGuard:
    async def test_sync_policy(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/vip")
        @fast.policy(lambda ctx: ctx.user.id == "user-1")
        async def endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"vip": "yes"}

        token = core.token_service.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/vip", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    async def test_sync_policy_denial(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/vip")
        @fast.policy(lambda ctx: ctx.user.id == "user-1")
        async def endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"vip": "yes"}

        token = core.token_service.create_access_token("user-2")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/vip", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_async_policy(self, auth_setup: tuple[FastAuth, Auth]) -> None:
        fast, core = auth_setup
        app = FastAPI()
        register_exception_handlers(app)

        async def check(ctx: AuthContext) -> bool:
            return ctx.has_role(admin_role)

        @app.get("/admin")
        @fast.policy(check)
        async def endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]: # pyright: ignore[reportUnusedFunction]
            return {"admin": "yes"}

        token = core.token_service.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
