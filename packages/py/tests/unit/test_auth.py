"""Tests for the framework-agnostic Auth class — sync and async overrides."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from urauth.auth import Auth
from urauth.authz.primitives import Action, Permission, Relation, RelationTuple, Resource, Role
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.exceptions import UnauthorizedError

# ── Shared primitives ───────────────────────────────────────────

read = Action("read")
write = Action("write")
delete = Action("delete")

user_res = Resource("user")
post_res = Resource("post")

can_read = Permission(user_res, read)
can_write = Permission(post_res, write)
can_delete = Permission(post_res, delete)

owns_post = Relation(post_res, "owner")

viewer = Role("viewer", [can_read])
editor = Role("editor", [can_read, can_write])
admin = Role("admin", [can_read, can_write, can_delete])

SECRET = "test-secret-key-for-testing-only-32chars"


@dataclass
class FakeUser:
    id: str = "user-1"
    email: str = "alice@test.com"
    is_active: bool = True
    roles: list[str] = field(default_factory=lambda: ["admin"])


# ── Sync Auth ───────────────────────────────────────────────────


class SyncAuth(Auth):
    def __init__(self, users: dict[str, FakeUser] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._users = users or {}

    def get_user(self, user_id: Any) -> Any | None:
        return self._users.get(str(user_id))

    def get_user_by_username(self, username: str) -> Any | None:
        for u in self._users.values():
            if u.email == username:
                return u
        return None

    def verify_password(self, user: Any, password: str) -> bool:
        return password == "secret"

    def get_user_roles(self, user: Any) -> list[Role]:
        return [admin] if "admin" in user.roles else [viewer]

    def get_user_permissions(self, user: Any) -> list[Permission]:
        return []

    def get_user_relations(self, user: Any) -> list[RelationTuple]:
        return [RelationTuple(owns_post, "42")]

    def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:
        return relation == owns_post and resource_id == "42"


# ── Async Auth ──────────────────────────────────────────────────


class AsyncAuth(Auth):
    def __init__(self, users: dict[str, FakeUser] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._users = users or {}

    async def get_user(self, user_id: Any) -> Any | None:  # type: ignore[override]
        return self._users.get(str(user_id))

    async def get_user_by_username(self, username: str) -> Any | None:  # type: ignore[override]
        for u in self._users.values():
            if u.email == username:
                return u
        return None

    async def verify_password(self, user: Any, password: str) -> bool:  # type: ignore[override]
        return password == "secret"

    async def get_user_roles(self, user: Any) -> list[Role]:  # type: ignore[override]
        return [admin] if "admin" in user.roles else [viewer]

    async def get_user_permissions(self, user: Any) -> list[Permission]:  # type: ignore[override]
        return [can_delete]  # direct permission

    async def get_user_relations(self, user: Any) -> list[RelationTuple]:  # type: ignore[override]
        return [RelationTuple(owns_post, "42")]

    async def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:  # type: ignore[override]
        return relation == owns_post and resource_id == "42"


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def alice() -> FakeUser:
    return FakeUser(id="user-1", email="alice@test.com", roles=["admin"])


@pytest.fixture
def bob() -> FakeUser:
    return FakeUser(id="user-2", email="bob@test.com", roles=["viewer"])


@pytest.fixture
def sync_auth(alice: FakeUser, bob: FakeUser) -> SyncAuth:
    return SyncAuth(
        users={alice.id: alice, bob.id: bob},
        config=AuthConfig(secret_key=SECRET),
        token_store=MemoryTokenStore(strict=False),
    )


@pytest.fixture
def async_auth(alice: FakeUser, bob: FakeUser) -> AsyncAuth:
    return AsyncAuth(
        users={alice.id: alice, bob.id: bob},
        config=AuthConfig(secret_key=SECRET),
        token_store=MemoryTokenStore(strict=False),
    )


# ── Sync Auth Tests ─────────────────────────────────────────────


class TestSyncAuth:
    def test_build_context_sync(self, sync_auth: SyncAuth) -> None:
        token = sync_auth.token_service.create_token_pair("user-1", roles=["admin"])
        ctx = sync_auth.build_context_sync(token.access_token)

        assert ctx.is_authenticated()
        assert ctx.user.id == "user-1"
        assert ctx.has_role(admin)
        assert ctx.has_permission(can_read)

    def test_build_context_sync_user_not_found(self, sync_auth: SyncAuth) -> None:
        token = sync_auth.token_service.create_token_pair("nonexistent")
        with pytest.raises(UnauthorizedError):
            sync_auth.build_context_sync(token.access_token)

    def test_build_context_sync_optional_no_token(self, sync_auth: SyncAuth) -> None:
        ctx = sync_auth.build_context_sync(None, optional=True)
        assert not ctx.is_authenticated()
        assert ctx.user is None

    def test_build_context_sync_optional_bad_token(self, sync_auth: SyncAuth) -> None:
        ctx = sync_auth.build_context_sync("garbage-token", optional=True)
        assert not ctx.is_authenticated()

    def test_check_relation_sync(self, sync_auth: SyncAuth, alice: FakeUser) -> None:
        assert sync_auth.check_relation_sync(alice, owns_post, "42") is True
        assert sync_auth.check_relation_sync(alice, owns_post, "99") is False

    def test_build_context_for_user_sync(self, sync_auth: SyncAuth, alice: FakeUser) -> None:
        ctx = sync_auth.build_context_for_user_sync(alice)
        assert ctx.is_authenticated()
        assert ctx.user is alice
        assert ctx.has_role(admin)


# ── Async Auth Tests ────────────────────────────────────────────


class TestAsyncAuth:
    async def test_build_context(self, async_auth: AsyncAuth) -> None:
        token = async_auth.token_service.create_token_pair("user-1", roles=["admin"])
        ctx = await async_auth.build_context(token.access_token)

        assert ctx.is_authenticated()
        assert ctx.user.id == "user-1"
        assert ctx.has_role(admin)

    async def test_build_context_merges_permissions(self, async_auth: AsyncAuth) -> None:
        token = async_auth.token_service.create_token_pair("user-1", roles=["admin"])
        ctx = await async_auth.build_context(token.access_token)

        # Admin role perms + direct can_delete permission
        assert ctx.has_permission(can_read)
        assert ctx.has_permission(can_write)
        assert ctx.has_permission(can_delete)

    async def test_build_context_user_not_found(self, async_auth: AsyncAuth) -> None:
        token = async_auth.token_service.create_token_pair("nonexistent")
        with pytest.raises(UnauthorizedError):
            await async_auth.build_context(token.access_token)

    async def test_build_context_no_token_raises(self, async_auth: AsyncAuth) -> None:
        with pytest.raises(UnauthorizedError):
            await async_auth.build_context(None)

    async def test_build_context_optional_no_token(self, async_auth: AsyncAuth) -> None:
        ctx = await async_auth.build_context(None, optional=True)
        assert not ctx.is_authenticated()

    async def test_build_context_optional_bad_token(self, async_auth: AsyncAuth) -> None:
        ctx = await async_auth.build_context("garbage", optional=True)
        assert not ctx.is_authenticated()

    async def test_build_context_inactive_user(self, async_auth: AsyncAuth) -> None:
        async_auth._users["user-1"].is_active = False  # pyright: ignore[reportPrivateUsage]
        token = async_auth.token_service.create_token_pair("user-1")
        with pytest.raises(UnauthorizedError, match="Inactive"):
            await async_auth.build_context(token.access_token)

    async def test_build_context_for_user(self, async_auth: AsyncAuth, alice: FakeUser) -> None:
        ctx = await async_auth.build_context_for_user(alice)
        assert ctx.is_authenticated()
        assert ctx.user is alice

    async def test_check_relation_async(self, async_auth: AsyncAuth, alice: FakeUser) -> None:
        from urauth.auth import maybe_await

        assert await maybe_await(async_auth.check_relation(alice, owns_post, "42")) is True
        assert await maybe_await(async_auth.check_relation(alice, owns_post, "99")) is False

    async def test_relations_in_context(self, async_auth: AsyncAuth) -> None:
        token = async_auth.token_service.create_token_pair("user-1")
        ctx = await async_auth.build_context(token.access_token)
        assert ctx.has_relation(owns_post, "42")
        assert not ctx.has_relation(owns_post, "99")


# ── Static requirement checks ───────────────────────────────────


class TestRequirementChecks:
    @pytest.fixture
    def ctx(self) -> AuthContext:
        return AuthContext(
            user=FakeUser(),
            roles=[admin, editor],
            permissions=admin.permissions,
        )

    def test_has_permission(self, ctx: AuthContext) -> None:
        assert ctx.has_permission(can_read) is True
        assert ctx.has_permission(Permission("unknown", "action")) is False

    def test_has_role(self, ctx: AuthContext) -> None:
        assert ctx.has_role(admin) is True
        assert ctx.has_role(viewer) is False

    def test_satisfies_permission(self, ctx: AuthContext) -> None:
        assert ctx.satisfies(can_read) is True

    def test_satisfies_role(self, ctx: AuthContext) -> None:
        assert ctx.satisfies(admin) is True
        assert ctx.satisfies(viewer) is False

    def test_satisfies_any(self, ctx: AuthContext) -> None:
        assert any(ctx.satisfies(r) for r in [viewer, can_read]) is True
        assert any(ctx.satisfies(r) for r in [viewer, Role("nobody")]) is False


# ── Mixed sync/async overrides ──────────────────────────────────


class TestMixedAuth:
    async def test_sync_get_user_async_roles(self) -> None:
        """Sync get_user + async get_user_roles in same class."""

        class MixedAuth(Auth):
            def get_user(self, user_id: Any) -> Any | None:
                return FakeUser(id=str(user_id))

            def get_user_by_username(self, username: str) -> Any | None:
                return FakeUser(email=username)

            def verify_password(self, user: Any, password: str) -> bool:
                return True

            async def get_user_roles(self, user: Any) -> list[Role]:  # type: ignore[override]
                return [admin]

        auth = MixedAuth(config=AuthConfig(secret_key=SECRET), token_store=MemoryTokenStore(strict=False))
        token = auth.token_service.create_token_pair("user-1")
        ctx = await auth.build_context(token.access_token)
        assert ctx.is_authenticated()
        assert ctx.has_role(admin)
