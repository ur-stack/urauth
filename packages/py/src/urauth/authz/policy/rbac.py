"""Role-Based Access Control policy."""

from __future__ import annotations

from ..context import AccessContext
from ..exceptions import ConfigurationError
from .base import Policy


class RBACPolicy(Policy):
    """Role-Based Access Control with role hierarchy support.

    Usage:
        rbac = RBACPolicy()
        rbac.grant("admin", "read", "write", "delete")
        rbac.grant("viewer", "read")
        rbac.inherit("admin", "viewer")  # admin inherits viewer's permissions
    """

    def __init__(self) -> None:
        self._role_permissions: dict[str, set[str]] = {}
        self._hierarchy: dict[str, set[str]] = {}  # child -> set of parents
        self._resolved_cache: dict[str, frozenset[str]] = {}

    def grant(self, role: str, *permissions: str) -> RBACPolicy:
        """Grant permissions to a role. Returns self for chaining."""
        if role not in self._role_permissions:
            self._role_permissions[role] = set()
        self._role_permissions[role].update(permissions)
        self._resolved_cache.clear()
        return self

    def inherit(self, child: str, parent: str) -> RBACPolicy:
        """Make child role inherit all permissions from parent role.

        Returns self for chaining.
        """
        if child == parent:
            raise ConfigurationError(
                f"Role '{child}' cannot inherit from itself"
            )
        if child not in self._hierarchy:
            self._hierarchy[child] = set()
        self._hierarchy[child].add(parent)
        self._resolved_cache.clear()
        self._detect_cycle(child, set())
        return self

    def _detect_cycle(self, role: str, visited: set[str]) -> None:
        """Detect cycles in role hierarchy."""
        if role in visited:
            raise ConfigurationError(
                f"Cycle detected in role hierarchy involving '{role}'"
            )
        visited.add(role)
        for parent in self._hierarchy.get(role, ()):
            self._detect_cycle(parent, visited.copy())

    def _resolve_permissions(self, role: str) -> frozenset[str]:
        """Resolve all permissions for a role including inherited ones."""
        if role in self._resolved_cache:
            return self._resolved_cache[role]

        perms: set[str] = set(self._role_permissions.get(role, ()))
        for parent in self._hierarchy.get(role, ()):
            perms |= self._resolve_permissions(parent)

        resolved = frozenset(perms)
        self._resolved_cache[role] = resolved
        return resolved

    async def evaluate(self, context: AccessContext) -> bool:
        """Check if any of the subject's roles grant the required action."""
        if context.action is None:
            return True

        all_permissions: set[str] = set()
        # Collect direct subject permissions
        all_permissions.update(context.subject.permissions)
        # Collect role-based permissions
        for role in context.subject.roles:
            all_permissions |= self._resolve_permissions(role)

        return context.action in all_permissions

    def description(self) -> str | None:
        roles = ", ".join(self._role_permissions.keys()) or "none"
        return f"RBAC policy (roles: {roles})"
