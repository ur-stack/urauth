"""Tests for single-string Permission constructor and string-form PermissionEnum."""

from __future__ import annotations

import pytest

from urauth.authz.permission_enum import PermissionEnum
from urauth.authz.primitives import Action, Permission, Resource
from urauth.context import AuthContext

# ── Single-string Permission ────────────────────────────────────


class TestPermissionStringForm:
    def test_single_string(self) -> None:
        p = Permission("user:read")
        assert str(p) == "user:read"
        assert str(p.resource) == "user"
        assert str(p.action) == "read"

    def test_single_string_equals_two_arg(self) -> None:
        p1 = Permission("user:read")
        p2 = Permission("user", "read")
        assert p1 == p2
        assert hash(p1) == hash(p2)

    def test_single_string_equals_raw_string(self) -> None:
        p = Permission("task:write")
        assert p == "task:write"

    def test_custom_separator(self) -> None:
        p = Permission("user.read", separator=".")
        assert str(p.resource) == "user"
        assert str(p.action) == "read"
        assert str(p) == "user:read"  # __str__ always uses ":"

    def test_invalid_string_no_separator(self) -> None:
        with pytest.raises(ValueError, match="must contain"):
            Permission("userread")

    def test_wildcard_permission(self) -> None:
        p = Permission("admin:*")
        assert str(p.resource) == "admin"
        assert str(p.action) == "*"

    def test_two_arg_still_works(self) -> None:
        p = Permission("user", "read")
        assert str(p) == "user:read"

    def test_two_arg_with_typed_args(self) -> None:
        p = Permission(Resource("user"), Action("read"))
        assert str(p) == "user:read"

    def test_composition(self) -> None:
        p1 = Permission("user:read")
        p2 = Permission("task:write")
        combined = p1 & p2
        assert len(combined.requirements) == 2

    def test_in_context(self) -> None:
        p = Permission("user:read")
        ctx = AuthContext(user=object(), permissions=[p])
        assert ctx.has_permission(p)
        assert ctx.has_permission("user:read")
        assert ctx.has_permission(Permission("user", "read"))


# ── String-form PermissionEnum ──────────────────────────────────


class TestPermissionEnumStringForm:
    def test_string_values(self) -> None:
        class Perms(PermissionEnum):
            USER_READ = "user:read"
            TASK_WRITE = "task:write"

        assert str(Perms.USER_READ) == "user:read"
        assert str(Perms.TASK_WRITE) == "task:write"

    def test_string_equals_tuple_form(self) -> None:
        class PermsA(PermissionEnum):
            USER_READ = "user:read"

        class PermsB(PermissionEnum):
            USER_READ = ("user", "read")

        assert PermsA.USER_READ == PermsB.USER_READ
        assert hash(PermsA.USER_READ) == hash(PermsB.USER_READ)

    def test_string_equals_raw_string(self) -> None:
        class Perms(PermissionEnum):
            USER_READ = "user:read"

        assert Perms.USER_READ == "user:read"

    def test_string_equals_permission(self) -> None:
        class Perms(PermissionEnum):
            USER_READ = "user:read"

        assert Permission("user:read") == Perms.USER_READ
        assert Permission("user", "read") == Perms.USER_READ

    def test_wildcard_string(self) -> None:
        class Perms(PermissionEnum):
            ADMIN_ALL = "admin:*"

        assert str(Perms.ADMIN_ALL) == "admin:*"
        assert Perms.ADMIN_ALL.value.action == "*"

    def test_tuple_form_still_works(self) -> None:
        class Perms(PermissionEnum):
            USER_READ = ("user", "read")

        assert str(Perms.USER_READ) == "user:read"

    def test_permission_object_still_works(self) -> None:
        class Perms(PermissionEnum):
            USER_READ = Permission("user", "read")

        assert str(Perms.USER_READ) == "user:read"

    def test_invalid_value(self) -> None:
        with pytest.raises(TypeError):

            class Perms(PermissionEnum):
                BAD = 42  # type: ignore[assignment]

    def test_in_context(self) -> None:
        class Perms(PermissionEnum):
            USER_READ = "user:read"
            TASK_WRITE = "task:write"

        ctx = AuthContext(
            user=object(),
            permissions=[Permission("user:read"), Permission("task:write")],
        )
        assert ctx.has_permission(Perms.USER_READ.value)
        assert ctx.has_permission(Perms.TASK_WRITE.value)
