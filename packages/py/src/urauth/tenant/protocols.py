"""Protocols for tenant hierarchy persistence and role provisioning."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from urauth.tenant.hierarchy import TenantPath


@runtime_checkable
class TenantStore(Protocol):
    """Protocol for tenant hierarchy persistence.

    Implement this to back the hierarchy with your database.
    """

    async def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        """Get a tenant node by ID."""
        ...

    async def get_ancestors(self, tenant_id: str) -> list[dict[str, Any]]:
        """Get all ancestors of a tenant, ordered root-first."""
        ...

    async def get_children(self, tenant_id: str) -> list[dict[str, Any]]:
        """Get immediate children of a tenant."""
        ...

    async def resolve_path(self, tenant_id: str) -> TenantPath | None:
        """Build a full TenantPath from root to the given tenant."""
        ...


@runtime_checkable
class TenantRoleProvisioner(Protocol):
    """Protocol for creating default roles when a tenant is created."""

    async def provision(
        self,
        tenant_id: str,
        level: str,
        templates: list[Any],
    ) -> None:
        """Create roles for a tenant from the given templates."""
        ...
