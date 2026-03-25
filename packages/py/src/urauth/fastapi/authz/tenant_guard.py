"""Tenant hierarchy guard for FastAPI.

Ensures the authenticated user belongs to the resolved tenant,
optionally at a specific hierarchy level and/or satisfying an
additional authorization requirement.

Usage::

    @auth.require_tenant()
    async def endpoint(ctx: AuthContext = Depends(auth.context)): ...

    @auth.require_tenant(level="organization")
    async def org_endpoint(ctx: AuthContext = Depends(auth.context)): ...

    @auth.require_tenant(requirement=Permission("org", "admin"))
    async def admin_endpoint(ctx: AuthContext = Depends(auth.context)): ...
"""

from __future__ import annotations

from starlette.requests import Request

from urauth.authz.primitives import Requirement
from urauth.context import AuthContext
from urauth.exceptions import ForbiddenError
from urauth.fastapi._guards import ContextResolver, _BaseGuard


class TenantGuard(_BaseGuard):
    """Guard ensuring user is within a tenant context.

    Optionally restricts to a specific hierarchy level and/or
    requires an additional authorization requirement.
    """

    def __init__(
        self,
        resolve_context: ContextResolver,
        *,
        level: str | None = None,
        requirement: Requirement | None = None,
    ) -> None:
        super().__init__(resolve_context)
        self._level = level
        self._requirement = requirement

    async def _check(self, ctx: AuthContext, request: Request) -> None:
        if ctx.tenant is None:
            raise ForbiddenError("No tenant context")
        if self._level is not None and ctx.tenant.leaf_level != self._level:
            raise ForbiddenError(f"Required tenant level: {self._level}")
        if self._requirement is not None and not ctx.satisfies(self._requirement):
            raise ForbiddenError()
