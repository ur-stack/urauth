"""Checker-based access control — the single concept for authorization."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from urauth.authz.primitives import Permission, match_permission
from urauth.context import AuthContext


@runtime_checkable
class PermissionChecker(Protocol):
    """Protocol for permission checkers.

    Implement this to plug in any authorization backend (Zanzibar, OPA, etc.).
    """

    async def has_permission(
        self,
        ctx: AuthContext,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        **kwargs: Any,
    ) -> bool: ...


class StringChecker:
    """Default checker — matches permissions semantically (separator-agnostic).

    Supports:
    - Exact match: ``"user:read"``
    - Wildcard: ``"*"`` grants everything
    - Resource wildcard: ``"user:*"`` grants all actions on ``user``
    """

    async def has_permission(
        self,
        ctx: AuthContext,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        **kwargs: Any,
    ) -> bool:
        required = Permission(resource, action)
        perms = ctx.permissions

        # If scoped, check scoped permissions first
        if scope is not None and scope in ctx.scopes:
            perms = ctx.scopes[scope]

        return any(match_permission(perm, required) for perm in perms)


class RoleExpandingChecker:
    """Expands roles via hierarchy, maps to permission objects, then checks.

    Replaces the old ``RBACManager`` + ``PermissionManager`` combination.
    """

    def __init__(
        self,
        role_permissions: dict[str, set[Permission]],
        *,
        hierarchy: dict[str, list[str]] | None = None,
    ) -> None:
        self._role_permissions = role_permissions
        self._hierarchy = hierarchy or {}
        self._expanded: dict[str, set[str]] = {}
        self._build_expansion()

    def _build_expansion(self) -> None:
        for role in self._hierarchy:
            self._expand(role, frozenset())

    def _expand(self, role: str, visiting: frozenset[str]) -> set[str]:
        if role in self._expanded:
            return self._expanded[role]
        if role in visiting:
            raise ValueError(f"Circular role hierarchy detected: {role}")
        result = {role}
        for child in self._hierarchy.get(role, []):
            result |= self._expand(child, visiting | {role})
        self._expanded[role] = result
        return result

    def effective_roles(self, user_roles: Sequence[str]) -> set[str]:
        """Return all roles a user effectively holds, including inherited ones."""
        result: set[str] = set()
        for role in user_roles:
            if role in self._expanded:
                result |= self._expanded[role]
            else:
                result.add(role)
        return result

    def _permissions_for_roles(self, roles: set[str]) -> set[Permission]:
        result: set[Permission] = set()
        for role in roles:
            result |= self._role_permissions.get(role, set())
        return result

    async def has_permission(
        self,
        ctx: AuthContext,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        **kwargs: Any,
    ) -> bool:
        role_names = [str(r) for r in ctx.roles]
        effective = self.effective_roles(role_names)
        perms = self._permissions_for_roles(effective)

        # Also include direct permissions from context
        perms |= set(ctx.permissions)

        required = Permission(resource, action)
        return any(match_permission(perm, required) for perm in perms)
