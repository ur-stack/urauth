"""Tests for checker-based access control, permission primitives, and RoleRegistry."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from urauth.authz.cache import MemoryRoleCache
from urauth.authz.checker import RoleExpandingChecker, StringChecker
from urauth.authz.permission_enum import PermissionEnum
from urauth.authz.primitives import Action, Permission, Resource, Role
from urauth.authz.roles import RoleRegistry
from urauth.context import AuthContext


@dataclass
class _User:
    id: str = "u1"


def _ctx(
    *,
    roles: list[Role] | None = None,
    permissions: list[Permission] | None = None,
    scopes: dict[str, list[Permission]] | None = None,
) -> AuthContext:
    """Helper to build an AuthContext for checker tests."""
    return AuthContext(
        user=_User(),
        roles=roles or [],
        permissions=permissions or [],
        scopes=scopes or {},
    )


# ── Permission primitives ────────────────────────────────────────


class TestPermissionPrimitives:
    def test_action_is_str(self) -> None:
        a = Action("read")
        assert a == "read"
        assert isinstance(a, str)

    def test_resource_is_str(self) -> None:
        r = Resource("user")
        assert r == "user"
        assert isinstance(r, str)

    def test_permission_str(self) -> None:
        p = Permission("user", "read")
        assert str(p) == "user:read"

    def test_permission_eq_str(self) -> None:
        p = Permission("user", "read")
        assert p == "user:read"
        assert "user:read" == p  # noqa: SIM300

    def test_permission_eq_permission(self) -> None:
        p1 = Permission("user", "read")
        p2 = Permission(Resource("user"), Action("read"))
        assert p1 == p2

    def test_permission_hash(self) -> None:
        p = Permission("user", "read")
        assert hash(p) == hash(Permission("user:read"))
        # Can be used in sets
        s = {p, Permission("user:read")}
        assert len(s) == 1

    def test_permission_ne(self) -> None:
        p = Permission("user", "read")
        assert p != "user:write"
        assert p != Permission("user", "write")

    def test_permission_repr(self) -> None:
        p = Permission("user", "read")
        assert "user" in repr(p)
        assert "read" in repr(p)

    def test_permission_subclass(self) -> None:
        class CustomPermission(Permission):
            def __init__(self, relation: str, resource_id: str):
                super().__init__(resource=resource_id, action=relation)
                self.relation = relation
                self.resource_id = resource_id

        cp = CustomPermission("editor", "doc-123")
        assert str(cp) == "doc-123:editor"
        assert cp.relation == "editor"
        assert cp.resource_id == "doc-123"


# ── PermissionEnum ───────────────────────────────────────────────


class TestPermissionEnum:
    def test_enum_from_strings(self) -> None:
        class P(PermissionEnum):
            USER_READ = ("user", "read")
            USER_WRITE = ("user", "write")

        assert str(P.USER_READ) == "user:read"
        assert P.USER_READ.value == Permission("user", "read")

    def test_enum_from_typed_primitives(self) -> None:
        user = Resource("user")
        read = Action("read")

        class P(PermissionEnum):
            USER_READ = (user, read)

        assert str(P.USER_READ) == "user:read"
        assert P.USER_READ == "user:read"

    def test_enum_eq_str(self) -> None:
        class P(PermissionEnum):
            TASK_READ = ("task", "read")

        assert P.TASK_READ == "task:read"

    def test_enum_eq_permission(self) -> None:
        class P(PermissionEnum):
            TASK_READ = ("task", "read")

        assert Permission("task", "read") == P.TASK_READ

    def test_enum_hash(self) -> None:
        class P(PermissionEnum):
            TASK_READ = ("task", "read")

        assert hash(P.TASK_READ) == hash(Permission("task:read"))
        s = {P.TASK_READ, Permission("task:read")}
        assert len(s) == 1

    def test_enum_members_are_distinct(self) -> None:
        class P(PermissionEnum):
            USER_READ = ("user", "read")
            TASK_READ = ("task", "read")

        assert P.USER_READ != P.TASK_READ


# ── StringChecker ────────────────────────────────────────────────


class TestStringChecker:
    @pytest.fixture
    def checker(self) -> StringChecker:
        return StringChecker()

    async def test_exact_match(self, checker: StringChecker) -> None:
        ctx = _ctx(permissions=[Permission("post", "read"), Permission("post", "write")])
        assert await checker.has_permission(ctx, "post", "read") is True
        assert await checker.has_permission(ctx, "post", "write") is True
        assert await checker.has_permission(ctx, "post", "delete") is False

    async def test_wildcard(self, checker: StringChecker) -> None:
        ctx = _ctx(permissions=[Permission("*")])
        assert await checker.has_permission(ctx, "anything", "goes") is True

    async def test_resource_wildcard(self, checker: StringChecker) -> None:
        ctx = _ctx(permissions=[Permission("post", "*")])
        assert await checker.has_permission(ctx, "post", "read") is True
        assert await checker.has_permission(ctx, "post", "delete") is True
        assert await checker.has_permission(ctx, "user", "read") is False

    async def test_empty_permissions(self, checker: StringChecker) -> None:
        ctx = _ctx(permissions=[])
        assert await checker.has_permission(ctx, "post", "read") is False

    async def test_semantic_match_across_separators(self) -> None:
        checker = StringChecker()
        ctx = _ctx(permissions=[Permission("post", "read")])
        # Semantic matching: "post:read" matches "post.read" regardless of separator
        assert await checker.has_permission(ctx, "post", "read") is True

    async def test_scoped_permissions(self, checker: StringChecker) -> None:
        ctx = _ctx(
            permissions=[Permission("post", "read")],
            scopes={
                "org-1": [Permission("post", "read"), Permission("post", "write")],
                "org-2": [Permission("post", "read")],
            },
        )
        assert await checker.has_permission(ctx, "post", "write") is False
        assert await checker.has_permission(ctx, "post", "write", scope="org-1") is True
        assert await checker.has_permission(ctx, "post", "write", scope="org-2") is False


# ── RoleExpandingChecker ─────────────────────────────────────────


class TestRoleExpandingChecker:
    @pytest.fixture
    def checker(self) -> RoleExpandingChecker:
        return RoleExpandingChecker(
            role_permissions={
                "admin": {Permission("*")},
                "editor": {Permission("post:read"), Permission("post:write")},
                "viewer": {Permission("post:read")},
            },
            hierarchy={"admin": ["editor"], "editor": ["viewer"]},
        )

    async def test_admin_has_all(self, checker: RoleExpandingChecker) -> None:
        ctx = _ctx(roles=[Role("admin")])
        assert await checker.has_permission(ctx, "anything", "goes") is True

    async def test_editor_permissions(self, checker: RoleExpandingChecker) -> None:
        ctx = _ctx(roles=[Role("editor")])
        assert await checker.has_permission(ctx, "post", "read") is True
        assert await checker.has_permission(ctx, "post", "write") is True
        assert await checker.has_permission(ctx, "post", "delete") is False

    async def test_viewer_permissions(self, checker: RoleExpandingChecker) -> None:
        ctx = _ctx(roles=[Role("viewer")])
        assert await checker.has_permission(ctx, "post", "read") is True
        assert await checker.has_permission(ctx, "post", "write") is False

    async def test_hierarchy_expansion(self, checker: RoleExpandingChecker) -> None:
        effective = checker.effective_roles(["admin"])
        assert effective == {"admin", "editor", "viewer"}

    async def test_deep_hierarchy(self) -> None:
        checker = RoleExpandingChecker(
            role_permissions={
                "superadmin": {Permission("nuke:launch")},
                "admin": {Permission("user:delete")},
                "viewer": {Permission("post:read")},
            },
            hierarchy={"superadmin": ["admin"], "admin": ["viewer"]},
        )
        ctx = _ctx(roles=[Role("superadmin")])
        assert await checker.has_permission(ctx, "post", "read") is True
        assert await checker.has_permission(ctx, "user", "delete") is True
        assert await checker.has_permission(ctx, "nuke", "launch") is True

    async def test_direct_permissions(self, checker: RoleExpandingChecker) -> None:
        ctx = _ctx(roles=[], permissions=[Permission("special", "access")])
        assert await checker.has_permission(ctx, "special", "access") is True

    async def test_unknown_role(self, checker: RoleExpandingChecker) -> None:
        ctx = _ctx(roles=[Role("nonexistent")])
        assert await checker.has_permission(ctx, "post", "read") is False

    async def test_multiple_roles(self, checker: RoleExpandingChecker) -> None:
        ctx = _ctx(roles=[Role("viewer"), Role("editor")])
        assert await checker.has_permission(ctx, "post", "write") is True

    async def test_resource_wildcard(self) -> None:
        checker = RoleExpandingChecker(
            role_permissions={"admin": {Permission("post:*")}},
        )
        ctx = _ctx(roles=[Role("admin")])
        assert await checker.has_permission(ctx, "post", "read") is True
        assert await checker.has_permission(ctx, "post", "delete") is True
        assert await checker.has_permission(ctx, "user", "read") is False

    async def test_accepts_permission_objects(self) -> None:
        """RoleExpandingChecker stores Permission objects directly."""
        checker = RoleExpandingChecker(
            role_permissions={
                "editor": {Permission("task", "read"), Permission("task", "write")},
            },
        )
        ctx = _ctx(roles=[Role("editor")])
        assert await checker.has_permission(ctx, "task", "read") is True
        assert await checker.has_permission(ctx, "task", "delete") is False


# ── RoleRegistry ─────────────────────────────────────────────────


class TestRoleRegistry:
    def test_static_role(self) -> None:
        reg = RoleRegistry()
        reg.role("admin", permissions=["*"])
        reg.role("viewer", permissions=["task:read"])

        checker = reg.build_checker()
        assert checker._role_permissions["admin"] == {Permission("*")}  # pyright: ignore[reportPrivateUsage]
        assert checker._role_permissions["viewer"] == {Permission("task:read")}  # pyright: ignore[reportPrivateUsage]

    def test_static_hierarchy(self) -> None:
        reg = RoleRegistry()
        reg.role("admin", permissions=["*"], inherits=["editor"])
        reg.role("editor", permissions=["task:read", "task:write"])

        checker = reg.build_checker()
        effective = checker.effective_roles(["admin"])
        assert effective == {"admin", "editor"}

    def test_include_merges_permissions(self) -> None:
        r1 = RoleRegistry()
        r1.role("editor", permissions=["task:read"])

        r2 = RoleRegistry()
        r2.role("editor", permissions=["task:write"])

        combined = RoleRegistry()
        combined.include(r1)
        combined.include(r2)

        checker = combined.build_checker()
        assert checker._role_permissions["editor"] == {Permission("task:read"), Permission("task:write")}  # pyright: ignore[reportPrivateUsage]

    def test_include_merges_hierarchy(self) -> None:
        r1 = RoleRegistry()
        r1.role("admin", permissions=["*"], inherits=["editor"])

        r2 = RoleRegistry()
        r2.role("admin", permissions=["*"], inherits=["viewer"])

        combined = RoleRegistry()
        combined.include(r1)
        combined.include(r2)

        checker = combined.build_checker()
        effective = checker.effective_roles(["admin"])
        assert "editor" in effective
        assert "viewer" in effective

    def test_permission_objects_in_registry(self) -> None:
        class P(PermissionEnum):
            TASK_READ = ("task", "read")
            TASK_WRITE = ("task", "write")

        reg = RoleRegistry()
        reg.role("editor", permissions=[P.TASK_READ, P.TASK_WRITE])

        checker = reg.build_checker()
        assert Permission("task:read") in checker._role_permissions["editor"]  # pyright: ignore[reportPrivateUsage]
        assert Permission("task:write") in checker._role_permissions["editor"]  # pyright: ignore[reportPrivateUsage]

    async def test_static_wins_over_loaded(self) -> None:
        class FakeLoader:
            async def load_roles(self) -> dict[str, set[str]]:
                return {"admin": {"task:read"}}

            async def load_hierarchy(self) -> dict[str, list[str]]:
                return {}

        reg = RoleRegistry()
        reg.role("admin", permissions=["*"])
        reg.with_loader(FakeLoader())
        await reg.load()

        checker = reg.build_checker()
        assert checker._role_permissions["admin"] == {Permission("*")}  # pyright: ignore[reportPrivateUsage]

    async def test_loaded_roles_available(self) -> None:
        class FakeLoader:
            async def load_roles(self) -> dict[str, set[str]]:
                return {"custom_role": {"report:read", "report:write"}}

            async def load_hierarchy(self) -> dict[str, list[str]]:
                return {}

        reg = RoleRegistry()
        reg.with_loader(FakeLoader())
        await reg.load()

        checker = reg.build_checker()
        assert Permission("report:read") in checker._role_permissions["custom_role"]  # pyright: ignore[reportPrivateUsage]
        assert Permission("report:write") in checker._role_permissions["custom_role"]  # pyright: ignore[reportPrivateUsage]


# ── MemoryRoleCache ──────────────────────────────────────────────


class TestMemoryRoleCache:
    async def test_get_set(self) -> None:
        cache = MemoryRoleCache()
        await cache.set("key", {"a": [1, 2]}, ttl=60)
        result = await cache.get("key")
        assert result == {"a": [1, 2]}

    async def test_miss(self) -> None:
        cache = MemoryRoleCache()
        assert await cache.get("nonexistent") is None

    async def test_invalidate(self) -> None:
        cache = MemoryRoleCache()
        await cache.set("key", {"a": 1}, ttl=60)
        await cache.invalidate("key")
        assert await cache.get("key") is None

    async def test_ttl_expiration(self) -> None:
        import time
        from unittest.mock import patch

        cache = MemoryRoleCache()
        await cache.set("key", {"a": 1}, ttl=10)

        assert await cache.get("key") == {"a": 1}

        with patch("urauth.authz.cache.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 20
            assert await cache.get("key") is None

    async def test_cache_with_registry(self) -> None:
        call_count = 0

        class CountingLoader:
            async def load_roles(self) -> dict[str, set[str]]:
                nonlocal call_count
                call_count += 1
                return {"viewer": {"task:read"}}

            async def load_hierarchy(self) -> dict[str, list[str]]:
                return {}

        cache = MemoryRoleCache()
        reg = RoleRegistry()
        reg.with_loader(CountingLoader(), cache=cache, cache_ttl=300)

        await reg.load()
        assert call_count == 1

        await reg.load()
        assert call_count == 1

        await reg.reload()
        assert call_count == 2
