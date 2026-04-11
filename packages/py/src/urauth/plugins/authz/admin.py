"""Admin authorization plugin.

Provides role-based admin checks and superuser utilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth
    from urauth.context import AuthContext


class AdminPlugin:
    """Admin role enforcement plugin.

    Registers a set of role names that grant administrative access and
    exposes helper methods on ``auth.admin``.

    Usage::

        from urauth.plugins.authz import AdminPlugin

        auth = Auth(
            plugins=[
                AdminPlugin(
                    admin_roles={"admin", "superuser"},
                    superuser_roles={"superuser"},
                )
            ],
            ...
        )

        # In a route handler
        if not auth.admin.is_admin(ctx):
            raise ForbiddenError("Admin only")

        # Or raise immediately
        auth.admin.require_admin(ctx)

        # Check for full superuser access
        auth.admin.require_superuser(ctx)
    """

    id = "admin"

    def __init__(
        self,
        *,
        admin_roles: set[str] | None = None,
        superuser_roles: set[str] | None = None,
    ) -> None:
        self.admin_roles: set[str] = admin_roles or {"admin"}
        self.superuser_roles: set[str] = superuser_roles or {"superuser"}

    def setup(self, auth: Auth) -> None:
        auth.admin = self

    def _role_names(self, context: AuthContext) -> set[str]:
        return {r.name for r in context.roles}

    def is_admin(self, context: AuthContext) -> bool:
        """Return ``True`` if the context has any admin or superuser role."""
        names = self._role_names(context)
        return bool(names & (self.admin_roles | self.superuser_roles))

    def is_superuser(self, context: AuthContext) -> bool:
        """Return ``True`` if the context has a superuser role."""
        return bool(self._role_names(context) & self.superuser_roles)

    def require_admin(self, context: AuthContext) -> None:
        """Raise :class:`~urauth.exceptions.ForbiddenError` if not an admin."""
        if not self.is_admin(context):
            from urauth.exceptions import ForbiddenError

            raise ForbiddenError("Administrator access required.")

    def require_superuser(self, context: AuthContext) -> None:
        """Raise :class:`~urauth.exceptions.ForbiddenError` if not a superuser."""
        if not self.is_superuser(context):
            from urauth.exceptions import ForbiddenError

            raise ForbiddenError("Superuser access required.")

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    async def on_login(self, user_id: str, method: str) -> None:
        pass  # Hook available for audit logging of admin logins downstream
