"""Tests for the FastAuth adapter — guards, context, decorators, Depends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from urauth.auth import Auth
from urauth.authz.primitives import Action, Permission, Relation, RelationTuple, Resource, Role
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth

# ── Shared primitives ───────────────────────────────────────────

read = Action("read")
write = Action("write")
delete = Action("delete")
invite = Action("invite")

user_res = Resource("user")
post_res = Resource("post")
org_res = Resource("organization")

can_read_users = Permission(user_res, read)
can_write_posts = Permission(post_res, write)
can_delete_posts = Permission(post_res, delete)
can_invite = Permission(org_res, invite)

owns_post = Relation(post_res, "owner")
member_of = Relation(org_res, "member")

viewer = Role("viewer", [can_read_users])
editor = Role("editor", [can_read_users, can_write_posts])
admin = Role("admin", [can_read_users, can_write_posts, can_delete_posts, can_invite])

SECRET = "test-secret-key-for-testing-only-32chars"


@dataclass
class FakeUser:
    id: str = "user-1"
    email: str = "alice@test.com"
    is_active: bool = True
    roles: list[str] = field(default_factory=lambda: ["admin"])


# ── Test Auth subclass ──────────────────────────────────────────


class _CoreAuth(Auth):
    def __init__(self, users: dict[str, FakeUser] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._users = users or {}

    async def get_user(self, user_id: Any) -> Any | None:
        return self._users.get(str(user_id))

    async def get_user_by_username(self, username: str) -> Any | None:
        return None

    def verify_password(self, user: Any, password: str) -> bool:
        return True

    async def get_user_roles(self, user: Any) -> list[Role]:  # type: ignore[override]
        role_map = {"admin": admin, "editor": editor, "viewer": viewer}
        return [role_map[r] for r in user.roles if r in role_map]

    async def get_user_relations(self, user: Any) -> list[RelationTuple]:  # type: ignore[override]
        return [RelationTuple(owns_post, "42"), RelationTuple(member_of, "acme")]

    async def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:  # type: ignore[override]
        return (relation, resource_id) in [(owns_post, "42"), (member_of, "acme")]


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def alice() -> FakeUser:
    return FakeUser(id="user-1", roles=["admin"])


@pytest.fixture
def bob() -> FakeUser:
    return FakeUser(id="user-2", email="bob@test.com", roles=["viewer"])


@pytest.fixture
def core_auth(alice: FakeUser, bob: FakeUser) -> _CoreAuth:
    return _CoreAuth(
        users={alice.id: alice, bob.id: bob},
        config=AuthConfig(secret_key=SECRET),
        token_store=MemoryTokenStore(strict=False),
    )


@pytest.fixture
def auth(core_auth: _CoreAuth) -> FastAuth:
    return FastAuth(core_auth)


def _make_token(auth: FastAuth, user_id: str, roles: list[str] | None = None) -> str:
    return auth.token_service.create_token_pair(user_id, roles=roles or []).access_token


# ── Test require() as decorator ─────────────────────────────────


class TestRequireDecorator:
    async def test_permission_allowed(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/users")
        @auth.require(can_read_users)
        async def list_users(ctx: AuthContext = Depends(auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"user": ctx.user.id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/users", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            assert resp.json()["user"] == "user-1"

    async def test_permission_denied(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/admin")
        @auth.require(can_delete_posts)
        async def admin_only(ctx: AuthContext = Depends(auth.context)) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-2", ["viewer"])
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_no_token_unauthorized(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/users")
        @auth.require(can_read_users)
        async def list_users(ctx: AuthContext = Depends(auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {}  # type: ignore[return-value]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/users")
            assert resp.status_code == 401

    async def test_role_guard(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/admin")
        @auth.require(admin)
        async def admin_stats(ctx: AuthContext = Depends(auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"role": "admin"}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            token = _make_token(auth, "user-2", ["viewer"])
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403


# ── Test req alias ──────────────────────────────────────────────


class TestReqAlias:
    def test_req_is_alias_for_require(self) -> None:
        assert FastAuth.req is FastAuth.require

    def test_req_any_is_alias_for_require_any(self) -> None:
        assert FastAuth.req_any is FastAuth.require_any

    def test_req_relation_is_alias_for_require_relation(self) -> None:
        assert FastAuth.req_relation is FastAuth.require_relation

    async def test_req_works_as_decorator(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/users")
        @auth.req(can_read_users)
        async def list_users(ctx: AuthContext = Depends(auth.context)) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/users", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200


# ── Test require() as Depends ───────────────────────────────────


class TestRequireDepends:
    async def test_permission_depends(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/users", dependencies=[Depends(auth.require(can_read_users))])
        async def list_users() -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/users", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    async def test_permission_denied_depends(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/admin", dependencies=[Depends(auth.require(can_delete_posts))])
        async def admin_only() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {}  # type: ignore[return-value]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-2", ["viewer"])
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_no_token_depends(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/users", dependencies=[Depends(auth.require(can_read_users))])
        async def list_users() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {}  # type: ignore[return-value]

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/users")
            assert resp.status_code == 401


# ── Test require_any ────────────────────────────────────────────


class TestRequireAny:
    async def test_any_permission_decorator(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.put("/posts/{post_id}")
        @auth.require_any(can_write_posts, admin)
        async def update(post_id: str, ctx: AuthContext = Depends(auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"updated": post_id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Admin can
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.put("/posts/1", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            # Viewer cannot
            token = _make_token(auth, "user-2", ["viewer"])
            resp = await client.put("/posts/1", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_any_depends(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.put("/posts/{post_id}", dependencies=[Depends(auth.req_any(can_write_posts, admin))])
        async def update(post_id: str) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"updated": post_id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.put("/posts/1", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200


# ── Test require_relation ───────────────────────────────────────


class TestRequireRelation:
    async def test_relation_decorator(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.delete("/posts/{post_id}")
        @auth.require_relation(owns_post, resource_id_from="post_id")
        async def delete_post(post_id: str, request: Request) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"deleted": post_id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            # User owns post 42
            resp = await client.delete("/posts/42", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            # User doesn't own post 99
            resp = await client.delete("/posts/99", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_relation_depends(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.delete(
            "/posts/{post_id}",
            dependencies=[Depends(auth.req_relation(owns_post, resource_id_from="post_id"))],
        )
        async def delete_post(post_id: str) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"deleted": post_id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.delete("/posts/42", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            resp = await client.delete("/posts/99", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403


# ── Test policy ─────────────────────────────────────────────────


class TestPolicy:
    async def test_policy_decorator(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.post("/orgs/{org_id}/invite")
        @auth.policy(
            lambda ctx: (
                ctx.has_permission(can_invite)
                and ctx.has_relation(member_of, ctx.path_params.get("org_id", ""))
            )
        )
        async def invite(org_id: str, ctx: AuthContext = Depends(auth.context)) -> dict[str, bool | str]:  # pyright: ignore[reportUnusedFunction]
            return {"invited": True, "org": org_id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            # Member of acme + has invite perm
            resp = await client.post("/orgs/acme/invite", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            # Not member of other-org
            resp = await client.post("/orgs/other-org/invite", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    async def test_policy_depends(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        def check(ctx: AuthContext) -> bool:
            return ctx.has_role(admin)

        @app.get("/admin", dependencies=[Depends(auth.policy(check))])
        async def admin_only() -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            token = _make_token(auth, "user-2", ["viewer"])
            resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403


# ── Test optional ───────────────────────────────────────────────


class TestOptional:
    async def test_optional_with_token(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/feed")
        @auth.optional
        async def feed(ctx: AuthContext = Depends(auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            if ctx.is_authenticated():
                return {"feed": "personalized", "user": ctx.user.id}
            return {"feed": "public"}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/feed", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            assert resp.json()["feed"] == "personalized"

    async def test_optional_without_token(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/feed")
        @auth.optional
        async def feed(ctx: AuthContext = Depends(auth.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            if ctx.is_authenticated():
                return {"feed": "personalized"}
            return {"feed": "public"}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/feed")
            assert resp.status_code == 200
            assert resp.json()["feed"] == "public"


# ── Test context dependency ─────────────────────────────────────


class TestContext:
    async def test_context_returns_full_info(self, auth: FastAuth) -> None:
        app = FastAPI()
        auth.init_app(app)

        @app.get("/me", dependencies=[Depends(auth.require(can_read_users))])
        async def me(ctx: AuthContext = Depends(auth.context)) -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
            return {
                "user": ctx.user.id,
                "roles": [r.name for r in ctx.roles],
                "perms": [str(p) for p in ctx.permissions],
                "relations": [(str(rt.relation), rt.object_id) for rt in ctx.relations],
            }

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["user"] == "user-1"
            assert "admin" in data["roles"]
            assert "user:read" in data["perms"]
            assert ["post#owner", "42"] in data["relations"]

    async def test_context_cached_on_request(self, auth: FastAuth) -> None:
        """Context should be built once and cached for the request."""
        app = FastAPI()
        auth.init_app(app)
        call_count = 0
        original_build = auth._auth.build_context  # pyright: ignore[reportPrivateUsage]

        async def counting_build(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            return await original_build(*args, **kwargs)

        auth._auth.build_context = counting_build  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]

        @app.get("/test", dependencies=[Depends(auth.require(can_read_users))])
        async def endpoint(ctx: AuthContext = Depends(auth.context)) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/test", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            # Guard builds once, context dep reads from cache
            assert call_count == 1

    async def test_direct_context_call(self, auth: FastAuth) -> None:
        """auth.context(request) works as a direct call."""
        app = FastAPI()
        auth.init_app(app)

        @app.get("/me")
        @auth.require(can_read_users)
        async def me(request: Request) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            ctx = await auth.context(request)
            return {"user": ctx.user.id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            token = _make_token(auth, "user-1", ["admin"])
            resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            assert resp.json()["user"] == "user-1"
