"""Organization (multi-tenant) authorization plugin.

Models organizations as the top level of urauth's tenant hierarchy.
Members have organization-scoped roles (owner, admin, member, viewer).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth
    from urauth.context import AuthContext


@dataclass
class OrgMembership:
    """Represents a user's membership in one organization."""

    org_id: str
    role: str  # "owner" | "admin" | "member" | "viewer"
    metadata: dict[str, Any] = field(default_factory=dict)


# Default organization role hierarchy
_DEFAULT_ROLES = {
    "owner": ["admin", "member", "viewer"],
    "admin": ["member", "viewer"],
    "member": ["viewer"],
    "viewer": [],
}


class OrganizationPlugin:
    """Multi-tenant organization management plugin.

    Wraps urauth's tenant system into an "organization" abstraction with
    standard membership roles: owner, admin, member, viewer.

    Usage::

        from urauth.plugins.authz import OrganizationPlugin

        auth = Auth(
            plugins=[OrganizationPlugin()],
            ...
        )

        # In a route: check org membership role
        auth.organization.require_role(ctx, org_id="org_123", role="admin")

        # Check if user is in org at all
        auth.organization.is_member(ctx, org_id="org_123")

        # Check if user is owner or admin
        auth.organization.is_org_admin(ctx, org_id="org_123")
    """

    id = "organization"

    def __init__(
        self,
        *,
        levels: list[str] | None = None,
        roles: dict[str, list[str]] | None = None,
    ) -> None:
        """
        Args:
            levels: Tenant hierarchy levels (default ``["org"]``).
                    Use ``["company", "department"]`` for nested orgs.
            roles: Role hierarchy mapping ``{role: [implied_roles]}``.
                   Defaults to owner > admin > member > viewer.
        """
        self.levels: list[str] = levels or ["org"]
        self.roles: dict[str, list[str]] = roles or _DEFAULT_ROLES

    def setup(self, auth: Auth) -> None:
        auth.tenant_enabled = True
        auth.tenant_hierarchy_enabled = len(self.levels) > 1
        auth.tenant_hierarchy_levels = self.levels
        auth.organization = self

    # ── Membership checks ─────────────────────────────────────────────────────

    def _org_role(self, context: AuthContext, org_id: str) -> str | None:
        """Return the user's role in *org_id*, or ``None`` if not a member."""
        if context.token is None:
            return None
        # org_id stored in tenant_id or tenant_path leaf
        if context.tenant is not None:
            for node in context.tenant:
                if node.id == org_id:
                    # Role is stored as a scope or extra claim — convention:
                    # extra claim "org_role" or the token's roles list.
                    if context.token.extra.get("org_id") == org_id:
                        return str(context.token.extra.get("org_role", "member"))
        # Fallback: check if tenant_id matches and return role from token extras
        if context.token.tenant_id == org_id:
            return str(context.token.extra.get("org_role", "member"))
        return None

    def _implied_roles(self, role: str) -> set[str]:
        """Return the set of roles implied by *role* (including itself)."""
        result: set[str] = {role}
        for implied in self.roles.get(role, []):
            result.update(self._implied_roles(implied))
        return result

    def is_member(self, context: AuthContext, *, org_id: str) -> bool:
        """Return ``True`` if the user is a member of *org_id* at any role."""
        return self._org_role(context, org_id) is not None

    def has_role(self, context: AuthContext, *, org_id: str, role: str) -> bool:
        """Return ``True`` if the user has at least *role* in *org_id*.

        Higher roles imply lower roles (owner implies admin, admin implies member, etc.).
        """
        actual = self._org_role(context, org_id)
        if actual is None:
            return False
        return role in self._implied_roles(actual)

    def is_org_admin(self, context: AuthContext, *, org_id: str) -> bool:
        """Return ``True`` if the user is an owner or admin of *org_id*."""
        return self.has_role(context, org_id=org_id, role="admin")

    def require_role(self, context: AuthContext, *, org_id: str, role: str) -> None:
        """Raise :class:`~urauth.exceptions.ForbiddenError` if the user lacks *role* in *org_id*."""
        if not self.has_role(context, org_id=org_id, role=role):
            from urauth.exceptions import ForbiddenError

            raise ForbiddenError(f"Role '{role}' required in organization '{org_id}'.")

    def require_member(self, context: AuthContext, *, org_id: str) -> None:
        """Raise :class:`~urauth.exceptions.ForbiddenError` if not a member of *org_id*."""
        self.require_role(context, org_id=org_id, role="viewer")

    def require_admin(self, context: AuthContext, *, org_id: str) -> None:
        """Raise :class:`~urauth.exceptions.ForbiddenError` if not an owner/admin of *org_id*."""
        self.require_role(context, org_id=org_id, role="admin")
