"""Protocols for role loading and caching."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RoleLoader(Protocol):
    """Protocol for loading roles from an external source (database, API, etc.)."""

    async def load_roles(self) -> dict[str, set[str]]:
        """Return a mapping of role name → set of permission strings."""
        ...

    async def load_hierarchy(self) -> dict[str, list[str]]:
        """Return a mapping of role name → list of child role names."""
        ...


@runtime_checkable
class RoleCache(Protocol):
    """Protocol for caching role data."""

    async def get(self, key: str) -> dict[str, Any] | None:
        """Retrieve cached data, or None if not cached / expired."""
        ...

    async def set(self, key: str, value: dict[str, Any], ttl: int) -> None:
        """Store data with a TTL in seconds."""
        ...

    async def invalidate(self, key: str) -> None:
        """Remove cached data."""
        ...
