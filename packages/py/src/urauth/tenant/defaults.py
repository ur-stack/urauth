"""Default role templates for tenant levels.

Allows defining what roles are auto-created when a new tenant is provisioned::

    defaults = TenantDefaults()
    defaults.register("organization", [
        RoleTemplate("employees", permissions=["org:read"]),
        RoleTemplate("clients", permissions=["org:read:public"]),
    ])
    defaults.register("group", [
        RoleTemplate("group_admin", permissions=["group:*"]),
        RoleTemplate("group_member", permissions=["group:read"]),
    ])

    # When creating a new organization tenant:
    await defaults.provision("org-123", "organization", provisioner)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from urauth.tenant.protocols import TenantRoleProvisioner


@dataclass(frozen=True, slots=True)
class RoleTemplate:
    """Blueprint for a default role to create in a new tenant."""

    name: str
    permissions: list[str] = field(default_factory=list)
    description: str = ""


class TenantDefaults:
    """Registry mapping tenant level names to default role templates."""

    def __init__(self) -> None:
        self._registry: dict[str, list[RoleTemplate]] = {}

    def register(self, level: str, templates: list[RoleTemplate]) -> None:
        """Register default role templates for a tenant level.

        Replaces any previously registered templates for this level.
        """
        self._registry[level] = list(templates)

    def templates_for(self, level: str) -> list[RoleTemplate]:
        """Get the registered templates for a level, or empty list."""
        return list(self._registry.get(level, []))

    async def provision(
        self,
        tenant_id: str,
        level: str,
        provisioner: TenantRoleProvisioner,
    ) -> None:
        """Create default roles for a tenant using the provisioner.

        Looks up templates for the given level and delegates creation
        to the provisioner protocol implementation.
        """
        templates = self._registry.get(level)
        if templates:
            await provisioner.provision(tenant_id, level, templates)

    @property
    def levels(self) -> list[str]:
        """Return all registered level names."""
        return list(self._registry.keys())

    def __repr__(self) -> str:
        counts = ", ".join(f"{k}: {len(v)} templates" for k, v in self._registry.items())
        return f"TenantDefaults({counts})"
