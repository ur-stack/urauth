"""Security tests for permission checkers — StringChecker, RoleExpandingChecker, and requirement composition.

Validates wildcard semantics, scoped permissions, role hierarchy expansion,
circular hierarchy detection, and AllOf/AnyOf composition edge cases.
"""

from __future__ import annotations

import pytest

from urauth.authz.checker import RoleExpandingChecker, StringChecker
from urauth.authz.primitives import AllOf, AnyOf, Permission, Role
from urauth.context import AuthContext


# ── StringChecker ────────────────────────────────────────────────


class TestStringCheckerSecurity:
    """Edge cases for the default string-based permission checker."""

    async def test_exact_permission_match(self) -> None:
        ctx = AuthContext(user="alice", permissions=[Permission("user", "read")])
        checker = StringChecker()
        assert await checker.has_permission(ctx, "user", "read") is True

    async def test_different_action_denied(self) -> None:
        ctx = AuthContext(user="alice", permissions=[Permission("user", "read")])
        checker = StringChecker()
        assert await checker.has_permission(ctx, "user", "write") is False

    async def test_global_wildcard_grants_everything(self) -> None:
        ctx = AuthContext(user="alice", permissions=[Permission("*")])
        checker = StringChecker()
        assert await checker.has_permission(ctx, "user", "read") is True
        assert await checker.has_permission(ctx, "doc", "delete") is True
        assert await checker.has_permission(ctx, "anything", "else") is True

    async def test_resource_wildcard_grants_all_actions(self) -> None:
        ctx = AuthContext(user="alice", permissions=[Permission("user", "*")])
        checker = StringChecker()
        assert await checker.has_permission(ctx, "user", "read") is True
        assert await checker.has_permission(ctx, "user", "write") is True
        assert await checker.has_permission(ctx, "user", "delete") is True
        # Does not grant other resources
        assert await checker.has_permission(ctx, "doc", "read") is False

    async def test_no_permissions_always_false(self) -> None:
        ctx = AuthContext(user="alice", permissions=[])
        checker = StringChecker()
        assert await checker.has_permission(ctx, "user", "read") is False
        assert await checker.has_permission(ctx, "anything", "else") is False

    async def test_scoped_permissions_used_when_scope_exists(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "read")],
            scopes={
                "tenant-a": [Permission("doc", "write")],
            },
        )
        checker = StringChecker()
        # With scope "tenant-a", uses scoped permissions (doc:write), not context permissions
        assert await checker.has_permission(ctx, "doc", "write", scope="tenant-a") is True
        assert await checker.has_permission(ctx, "user", "read", scope="tenant-a") is False

    async def test_scoped_permissions_fallback_when_scope_missing(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "read")],
            scopes={
                "tenant-a": [Permission("doc", "write")],
            },
        )
        checker = StringChecker()
        # Scope "unknown" not in ctx.scopes, falls back to context permissions
        assert await checker.has_permission(ctx, "user", "read", scope="unknown") is True
        assert await checker.has_permission(ctx, "doc", "write", scope="unknown") is False


# ── RoleExpandingChecker ─────────────────────────────────────────


class TestRoleExpandingCheckerSecurity:
    """Edge cases for role expansion and hierarchy-based permission checks."""

    async def test_role_hierarchy_expansion(self) -> None:
        """admin includes editor, editor includes viewer — admin gets all permissions."""
        role_permissions = {
            "admin": {Permission("admin", "panel")},
            "editor": {Permission("doc", "write")},
            "viewer": {Permission("doc", "read")},
        }
        hierarchy = {
            "admin": ["editor"],
            "editor": ["viewer"],
        }
        checker = RoleExpandingChecker(role_permissions, hierarchy=hierarchy)
        ctx = AuthContext(user="alice", roles=[Role("admin")])

        assert await checker.has_permission(ctx, "admin", "panel") is True
        assert await checker.has_permission(ctx, "doc", "write") is True
        assert await checker.has_permission(ctx, "doc", "read") is True

    def test_circular_hierarchy_raises(self) -> None:
        """Circular hierarchy (admin -> editor -> admin) raises ValueError, not infinite loop."""
        role_permissions = {
            "admin": {Permission("admin", "panel")},
            "editor": {Permission("doc", "write")},
        }
        hierarchy = {
            "admin": ["editor"],
            "editor": ["admin"],
        }
        with pytest.raises(ValueError, match="Circular role hierarchy detected"):
            RoleExpandingChecker(role_permissions, hierarchy=hierarchy)

    async def test_unknown_role_still_included(self) -> None:
        """A role not in the hierarchy is still returned as-is by effective_roles."""
        role_permissions = {
            "admin": {Permission("admin", "panel")},
            "mystery": {Permission("secret", "access")},
        }
        checker = RoleExpandingChecker(role_permissions, hierarchy={})
        ctx = AuthContext(user="alice", roles=[Role("mystery")])

        # "mystery" not in hierarchy but still expands to itself
        effective = checker.effective_roles(["mystery"])
        assert "mystery" in effective

        # Permissions from that role are checked
        assert await checker.has_permission(ctx, "secret", "access") is True

    async def test_direct_permissions_always_included(self) -> None:
        """Direct permissions from context are included alongside role-based permissions."""
        role_permissions = {
            "viewer": {Permission("doc", "read")},
        }
        checker = RoleExpandingChecker(role_permissions, hierarchy={})
        ctx = AuthContext(
            user="alice",
            roles=[Role("viewer")],
            permissions=[Permission("user", "write")],  # direct permission
        )

        # Role-based
        assert await checker.has_permission(ctx, "doc", "read") is True
        # Direct from context
        assert await checker.has_permission(ctx, "user", "write") is True

    async def test_empty_roles_no_role_permissions(self) -> None:
        """Empty role list means no role-based permissions, only direct ones."""
        role_permissions = {
            "admin": {Permission("admin", "panel")},
        }
        checker = RoleExpandingChecker(role_permissions, hierarchy={})
        ctx = AuthContext(user="alice", roles=[], permissions=[])

        assert await checker.has_permission(ctx, "admin", "panel") is False


# ── Requirement composition ──────────────────────────────────────


class TestRequirementComposition:
    """AllOf and AnyOf composition edge cases."""

    def test_allof_empty_is_vacuous_truth(self) -> None:
        ctx = AuthContext(user="alice", permissions=[])
        composite = AllOf([])
        assert composite.evaluate(ctx) is True

    def test_anyof_empty_is_false(self) -> None:
        ctx = AuthContext(user="alice", permissions=[])
        composite = AnyOf([])
        assert composite.evaluate(ctx) is False

    def test_allof_requires_all(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "read")],
        )
        read = Permission("user", "read")
        write = Permission("user", "write")

        # Only has read, AllOf(read, write) should fail
        composite = AllOf([read, write])
        assert composite.evaluate(ctx) is False

        # Give both
        ctx2 = AuthContext(
            user="alice",
            permissions=[Permission("user", "read"), Permission("user", "write")],
        )
        assert composite.evaluate(ctx2) is True

    def test_anyof_requires_any(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "read")],
        )
        read = Permission("user", "read")
        write = Permission("user", "write")

        # Has read, AnyOf(read, write) should pass
        composite = AnyOf([read, write])
        assert composite.evaluate(ctx) is True

        # Has neither
        ctx_empty = AuthContext(user="alice", permissions=[])
        assert composite.evaluate(ctx_empty) is False
