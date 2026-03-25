"""AuthContext — holds all auth data for the current user session."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from urauth.authz.primitives import Permission, Relation, RelationTuple, Requirement, Role, match_permission
from urauth.tenant.hierarchy import TenantPath
from urauth.types import TokenPayload


@dataclass
class AuthContext:
    """Context for the current authenticated (or anonymous) user session.

    Built automatically by ``Auth.context()`` from the request's JWT.
    Provides introspection methods for checking permissions, roles, and relations.
    """

    user: Any
    roles: list[Role] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    relations: list[RelationTuple] = field(default_factory=list)
    scopes: dict[str, list[Permission]] = field(default_factory=dict)
    token: TokenPayload | None = None
    request: Any = None
    tenant: TenantPath | None = None
    _authenticated: bool = True

    @staticmethod
    def anonymous(*, request: Any = None) -> AuthContext:
        """Create an anonymous (unauthenticated) context."""
        return AuthContext(
            user=None,
            _authenticated=False,
            request=request,
        )

    def is_authenticated(self) -> bool:
        return self._authenticated and self.user is not None

    def has_permission(self, permission: Permission | str) -> bool:
        """Check if the context holds a permission (supports wildcards).

        Comparison is semantic — separator-agnostic.
        """
        target = permission if isinstance(permission, Permission) else Permission(str(permission))
        return any(match_permission(p, target) for p in self.permissions)

    def has_role(self, role: Role | str) -> bool:
        """Check if the context holds a specific role."""
        name = role.name if isinstance(role, Role) else str(role)
        return any(r.name == name for r in self.roles)

    def has_any_role(self, *roles: Role | str) -> bool:
        """Check if the context holds any of the given roles."""
        return any(self.has_role(r) for r in roles)

    def has_relation(self, relation: Relation, resource_id: str) -> bool:
        """Check if the context holds a specific Zanzibar relation to a resource."""
        return any(rt.relation == relation and rt.object_id == resource_id for rt in self.relations)

    def satisfies(self, requirement: Requirement) -> bool:
        """Evaluate a (possibly composite) requirement against this context.

        Usage::

            ctx.satisfies(can_read & member_of | admin)
        """
        return requirement.evaluate(self)

    @property
    def tenant_id(self) -> str | None:
        """The leaf tenant ID (backward compat with flat tenant_id)."""
        if self.tenant is not None:
            return self.tenant.leaf_id
        if self.token is not None:
            return self.token.tenant_id
        return None

    def in_tenant(self, tenant_id: str) -> bool:
        """Check if the current context is within a specific tenant (at any level)."""
        if self.tenant is None:
            return False
        return self.tenant.is_descendant_of(tenant_id)

    def at_level(self, level: str) -> str | None:
        """Get the tenant ID at a specific hierarchy level."""
        if self.tenant is None:
            return None
        return self.tenant.id_at(level)

    @property
    def path_params(self) -> dict[str, str]:
        """Access the request's path parameters."""
        if self.request is not None:
            return dict(getattr(self.request, "path_params", {}))
        return {}
