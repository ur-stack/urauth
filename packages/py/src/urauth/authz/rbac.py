"""Role-based access control with role hierarchy."""

from __future__ import annotations


class RBACManager:
    """Manages a role hierarchy and checks role requirements.

    Hierarchy example::

        {"admin": ["editor", "viewer"]}

    means ``admin`` inherits all permissions of ``editor`` and ``viewer``.
    """

    def __init__(self, hierarchy: dict[str, list[str]] | None = None) -> None:
        self._hierarchy = hierarchy or {}
        self._expanded: dict[str, set[str]] = {}
        self._build_expansion()

    def _build_expansion(self) -> None:
        """Pre-compute the transitive closure of role inheritance."""
        for role in self._hierarchy:
            self._expanded[role] = self._expand(role)

    def _expand(self, role: str) -> set[str]:
        if role in self._expanded:
            return self._expanded[role]
        result = {role}
        for child in self._hierarchy.get(role, []):
            result |= self._expand(child)
        self._expanded[role] = result
        return result

    def effective_roles(self, user_roles: list[str]) -> set[str]:
        """Return all roles a user effectively holds, including inherited ones."""
        result: set[str] = set()
        for role in user_roles:
            if role in self._expanded:
                result |= self._expanded[role]
            else:
                result.add(role)
        return result

    def check_roles(self, user_roles: list[str], required: list[str]) -> bool:
        """Return True if the user holds at least one of the required roles."""
        effective = self.effective_roles(user_roles)
        return bool(effective & set(required))
