"""RoleRegistry — composable, FastAPI-like role management."""

from __future__ import annotations

from .checker import RoleExpandingChecker
from .loader import RoleCache, RoleLoader
from .permission_enum import PermissionEnum
from .primitives import Permission


class RoleRegistry:
    """Composable registry for role definitions.

    Supports static roles, merging via ``include()``, and DB-loaded roles with caching.
    """

    _CACHE_KEY_ROLES = "role_permissions"
    _CACHE_KEY_HIERARCHY = "role_hierarchy"

    def __init__(self) -> None:
        self._static_roles: dict[str, set[str]] = {}
        self._static_hierarchy: dict[str, list[str]] = {}
        self._loaded_roles: dict[str, set[str]] = {}
        self._loaded_hierarchy: dict[str, list[str]] = {}
        self._loader: RoleLoader | None = None
        self._cache: RoleCache | None = None
        self._cache_ttl: int = 300

    def role(
        self,
        name: str,
        permissions: list[str | Permission | PermissionEnum] | set[str | Permission | PermissionEnum],
        *,
        inherits: list[str] | None = None,
    ) -> None:
        """Register a static role."""
        self._static_roles[name] = {str(p) for p in permissions}
        if inherits:
            self._static_hierarchy[name] = list(inherits)

    def include(self, other: RoleRegistry) -> None:
        """Merge another registry (additive: permissions union, hierarchy merge)."""
        for name, perms in other._static_roles.items():
            if name in self._static_roles:
                self._static_roles[name] |= perms
            else:
                self._static_roles[name] = set(perms)
        for name, children in other._static_hierarchy.items():
            if name in self._static_hierarchy:
                existing = set(self._static_hierarchy[name])
                existing.update(children)
                self._static_hierarchy[name] = list(existing)
            else:
                self._static_hierarchy[name] = list(children)

    def with_loader(
        self,
        loader: RoleLoader,
        *,
        cache: RoleCache | None = None,
        cache_ttl: int = 300,
    ) -> None:
        """Configure DB loading with optional caching."""
        self._loader = loader
        self._cache = cache
        self._cache_ttl = cache_ttl

    async def load(self) -> None:
        """Load roles from the configured loader (via cache if available)."""
        if self._loader is None:
            return

        roles: dict[str, set[str]] | None = None
        hierarchy: dict[str, list[str]] | None = None

        if self._cache is not None:
            cached_roles = await self._cache.get(self._CACHE_KEY_ROLES)
            cached_hierarchy = await self._cache.get(self._CACHE_KEY_HIERARCHY)
            if cached_roles is not None and cached_hierarchy is not None:
                roles = {k: set(v) for k, v in cached_roles.items()}
                hierarchy = cached_hierarchy

        if roles is None:
            roles = await self._loader.load_roles()
            hierarchy = await self._loader.load_hierarchy()
            if self._cache is not None:
                await self._cache.set(
                    self._CACHE_KEY_ROLES,
                    {k: list(v) for k, v in roles.items()},
                    self._cache_ttl,
                )
                await self._cache.set(
                    self._CACHE_KEY_HIERARCHY,
                    hierarchy,  # type: ignore[arg-type]
                    self._cache_ttl,
                )

        self._loaded_roles = roles
        self._loaded_hierarchy = hierarchy or {}

    async def reload(self) -> None:
        """Invalidate cache and re-load from the loader."""
        if self._cache is not None:
            await self._cache.invalidate(self._CACHE_KEY_ROLES)
            await self._cache.invalidate(self._CACHE_KEY_HIERARCHY)
        await self.load()

    def _merged_roles(self) -> dict[str, set[str]]:
        """Merge loaded roles with static roles. Static takes precedence."""
        merged = dict(self._loaded_roles)
        for name, perms in self._static_roles.items():
            merged[name] = perms  # static wins
        return merged

    def _merged_hierarchy(self) -> dict[str, list[str]]:
        """Merge loaded hierarchy with static hierarchy. Static takes precedence."""
        merged = dict(self._loaded_hierarchy)
        for name, children in self._static_hierarchy.items():
            merged[name] = children  # static wins
        return merged

    def build_checker(self) -> RoleExpandingChecker:
        """Produce a configured ``RoleExpandingChecker`` from current state."""
        return RoleExpandingChecker(
            role_permissions=self._merged_roles(),
            hierarchy=self._merged_hierarchy(),
        )
