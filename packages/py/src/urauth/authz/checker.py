"""Checker-based access control — the single concept for authorization."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from urauth.authz.primitives import match_permission
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
    """Default checker — matches ``"resource:action"`` against context permissions.

    Supports:
    - Exact match: ``"user:read"``
    - Wildcard: ``"*"`` grants everything
    - Resource wildcard: ``"user:*"`` grants all actions on ``user``
    """

    def __init__(self, *, separator: str = ":") -> None:
        self._sep = separator

    async def has_permission(
        self,
        ctx: AuthContext,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        **kwargs: Any,
    ) -> bool:
        required = f"{resource}{self._sep}{action}"
        perms = [str(p) for p in ctx.permissions]

        # If scoped, check scoped permissions first
        if scope is not None and scope in ctx.scopes:
            perms = [str(p) for p in ctx.scopes[scope]]

        return any(match_permission(perm, required, separator=self._sep) for perm in perms)


class RoleExpandingChecker:
    """Expands roles via hierarchy, maps to permission strings, then checks.

    Replaces the old ``RBACManager`` + ``PermissionManager`` combination.
    """

    def __init__(
        self,
        role_permissions: dict[str, set[str]],
        *,
        hierarchy: dict[str, list[str]] | None = None,
        separator: str = ":",
    ) -> None:
        # Normalize Permission objects to strings at init time
        self._role_permissions = {role: {str(p) for p in perms} for role, perms in role_permissions.items()}
        self._hierarchy = hierarchy or {}
        self._sep = separator
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

    def _permissions_for_roles(self, roles: set[str]) -> set[str]:
        result: set[str] = set()
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
        perms |= {str(p) for p in ctx.permissions}

        required = f"{resource}{self._sep}{action}"
        return any(match_permission(perm, required, separator=self._sep) for perm in perms)
