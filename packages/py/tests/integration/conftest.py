"""Integration test fixtures — full FastAPI app with auth setup."""

from __future__ import annotations

from collections.abc import AsyncIterator
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
from urauth.fastapi.middleware import CSRFMiddleware

# ── Primitives ──────────────────────────────────────────────────

read = Action("read")
write = Action("write")
delete = Action("delete")
manage = Action("manage")

user_res = Resource("user")
task_res = Resource("task")
admin_res = Resource("admin")

user_read = Permission(user_res, read)
task_read = Permission(task_res, read)
task_write = Permission(task_res, write)
task_delete = Permission(task_res, delete)
admin_manage = Permission(admin_res, manage)

owns_task = Relation("owner", task_res)
member_of = Relation("member", Resource("org"))

viewer_role = Role("viewer", [user_read, task_read])
editor_role = Role("editor", [user_read, task_read, task_write])
admin_role = Role("admin", [user_read, task_read, task_write, task_delete, admin_manage])


# ── Fake Users ──────────────────────────────────────────────────


@dataclass
class IntegrationUser:
    id: str
    email: str
    password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)
    relations: list[tuple[Relation, str]] = field(default_factory=list)


USERS: dict[str, IntegrationUser] = {
    "admin-1": IntegrationUser(
        id="admin-1",
        email="admin@test.com",
        password="admin-pass",
        roles=["admin"],
        relations=[(owns_task, "task-1")],
    ),
    "editor-1": IntegrationUser(
        id="editor-1",
        email="editor@test.com",
        password="editor-pass",
        roles=["editor"],
        relations=[(member_of, "org-1")],
    ),
    "viewer-1": IntegrationUser(
        id="viewer-1",
        email="viewer@test.com",
        password="viewer-pass",
        roles=["viewer"],
    ),
    "inactive-1": IntegrationUser(
        id="inactive-1",
        email="inactive@test.com",
        password="pass",
        is_active=False,
        roles=["viewer"],
    ),
}

ROLE_MAP = {
    "admin": admin_role,
    "editor": editor_role,
    "viewer": viewer_role,
}

SECRET = "integration-test-secret-key-32ch"


# ── Auth Implementation ─────────────────────────────────────────


class IntegrationAuth(Auth):
    def __init__(self, users: dict[str, IntegrationUser], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._users = users
        self._by_email = {u.email: u for u in users.values()}

    async def get_user(self, user_id: Any) -> IntegrationUser | None:
        return self._users.get(str(user_id))

    async def get_user_by_username(self, username: str) -> IntegrationUser | None:
        return self._by_email.get(username)

    async def verify_password(self, user: Any, password: str) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        return user.password == password

    def get_user_roles(self, user: Any) -> list[Role]:
        return [ROLE_MAP[r] for r in user.roles if r in ROLE_MAP]

    def get_user_permissions(self, user: Any) -> list[Permission]:
        return []

    def get_user_relations(self, user: Any) -> list[tuple[Relation, str]]:
        return user.relations

    def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:
        return any(r == relation and rid == resource_id for r, rid in user.relations)


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def token_store() -> MemoryTokenStore:
    return MemoryTokenStore()


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key=SECRET)


@pytest.fixture
def core_auth(config: AuthConfig, token_store: MemoryTokenStore) -> IntegrationAuth:
    return IntegrationAuth(dict(USERS), config=config, token_store=token_store)


@pytest.fixture
def fast_auth(core_auth: IntegrationAuth) -> FastAuth:
    return FastAuth(core_auth)


def build_app(
    fast_auth: FastAuth,
    *,
    csrf: bool = False,
) -> FastAPI:
    """Create a fully wired FastAPI app for integration testing."""
    app = FastAPI()
    register_exception_handlers(app)

    if csrf:
        app.add_middleware(CSRFMiddleware, config=fast_auth.config)

    # Auth router (login/refresh/logout)
    app.include_router(fast_auth.password_auth_router())

    # Protected endpoint
    @app.get("/me")
    async def me(ctx: AuthContext = Depends(fast_auth.context)) -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
        return {
            "user_id": ctx.user.id,
            "roles": [str(r) for r in ctx.roles],
            "authenticated": ctx.is_authenticated(),
        }

    # Optional auth endpoint
    @app.get("/feed")
    @fast_auth.optional
    async def feed(ctx: AuthContext = Depends(fast_auth.context)) -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
        if ctx.is_authenticated():
            return {"type": "personalized", "user_id": ctx.user.id}
        return {"type": "public"}

    # Admin-only endpoint
    @app.get("/admin")
    @fast_auth.require(admin_manage)
    async def admin_panel(ctx: AuthContext = Depends(fast_auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"panel": "admin"}

    # Viewer endpoint
    @app.get("/tasks")
    @fast_auth.require(task_read)
    async def list_tasks(ctx: AuthContext = Depends(fast_auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"tasks": "list"}

    # Editor endpoint
    @app.post("/tasks")
    @fast_auth.require(task_write)
    async def create_task(ctx: AuthContext = Depends(fast_auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"task": "created"}

    # Relation-guarded endpoint
    @app.get("/tasks/{task_id}")
    @fast_auth.require_relation(owns_task, resource_id_from="task_id")
    async def get_task(task_id: str, ctx: AuthContext = Depends(fast_auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"task_id": task_id}

    return app


@pytest.fixture
def app(fast_auth: FastAuth) -> FastAPI:
    return build_app(fast_auth)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def login(client: AsyncClient, email: str, password: str) -> dict[str, Any]:
    """Helper: POST /auth/login and return response JSON."""
    resp = await client.post("/auth/login", json={"username": email, "password": password})
    return {"status": resp.status_code, "body": resp.json() if resp.status_code == 200 else None, "response": resp}
