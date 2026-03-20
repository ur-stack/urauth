"""Tests for RBAC and permission managers."""

from __future__ import annotations

from urauth.authz.permissions import PermissionManager
from urauth.authz.rbac import RBACManager


class TestRBACManager:
    def test_flat_roles(self) -> None:
        rbac = RBACManager()
        assert rbac.check_roles(["admin"], ["admin"])
        assert not rbac.check_roles(["viewer"], ["admin"])

    def test_hierarchy(self) -> None:
        rbac = RBACManager({"admin": ["editor", "viewer"]})
        # admin inherits editor
        assert rbac.check_roles(["admin"], ["editor"])
        assert rbac.check_roles(["admin"], ["viewer"])
        # editor does NOT inherit admin
        assert not rbac.check_roles(["editor"], ["admin"])

    def test_deep_hierarchy(self) -> None:
        rbac = RBACManager(
            {
                "super_admin": ["admin"],
                "admin": ["editor"],
                "editor": ["viewer"],
            }
        )
        assert rbac.check_roles(["super_admin"], ["viewer"])
        assert rbac.check_roles(["super_admin"], ["editor"])
        assert not rbac.check_roles(["viewer"], ["super_admin"])

    def test_effective_roles(self) -> None:
        rbac = RBACManager({"admin": ["editor", "viewer"]})
        effective = rbac.effective_roles(["admin"])
        assert effective == {"admin", "editor", "viewer"}


class TestPermissionManager:
    def test_basic(self) -> None:
        pm = PermissionManager(
            {
                "admin": {"*"},
                "editor": {"posts:read", "posts:write"},
                "viewer": {"posts:read"},
            }
        )
        assert pm.user_has_permission(["admin"], "anything")
        assert pm.user_has_permission(["editor"], "posts:write")
        assert not pm.user_has_permission(["viewer"], "posts:write")

    def test_multiple_roles(self) -> None:
        pm = PermissionManager(
            {
                "editor": {"posts:write"},
                "commenter": {"comments:write"},
            }
        )
        assert pm.user_has_permission(["editor", "commenter"], "posts:write")
        assert pm.user_has_permission(["editor", "commenter"], "comments:write")
        assert not pm.user_has_permission(["editor", "commenter"], "users:delete")

    def test_unknown_role(self) -> None:
        pm = PermissionManager({"admin": {"*"}})
        assert not pm.user_has_permission(["unknown"], "anything")
