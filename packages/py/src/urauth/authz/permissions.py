"""Permission-based authorization with role→permission mapping."""

from __future__ import annotations


class PermissionManager:
    """Maps roles to fine-grained permissions.

    Example::

        PermissionManager({
            "admin": {"*"},
            "editor": {"posts:read", "posts:write"},
            "viewer": {"posts:read"},
        })

    Wildcard ``*`` grants all permissions.
    """

    def __init__(self, role_permissions: dict[str, set[str]]) -> None:
        self._mapping = role_permissions

    def permissions_for_roles(self, roles: list[str]) -> set[str]:
        """Return the union of all permissions granted by the given roles."""
        result: set[str] = set()
        for role in roles:
            result |= self._mapping.get(role, set())
        return result

    def user_has_permission(self, user_roles: list[str], required: str) -> bool:
        """Return True if the user's roles grant the required permission."""
        perms = self.permissions_for_roles(user_roles)
        if "*" in perms:
            return True
        return required in perms
