from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request

from urauth.backends.base import TokenStore, UserFunctions
from urauth.exceptions import ForbiddenError, UnauthorizedError
from urauth.fastapi.transport.base import Transport
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPayload


class CurrentUserDependency:
    """Factory for FastAPI Depends() callables that resolve the current user.

    Usage::

        get_user = CurrentUserDependency(token_service, transport, backend, token_store)
        # then in FastAPIAuth:
        auth.current_user()  -> Depends(get_user())
        auth.current_user(roles=["admin"])  -> Depends(get_user(roles=["admin"]))
    """

    def __init__(
        self,
        token_service: TokenService,
        transport: Transport,
        user_fns: UserFunctions,
        token_store: TokenStore | None = None,
        rbac_manager: Any | None = None,
        permission_manager: Any | None = None,
    ) -> None:
        self._token_service = token_service
        self._transport = transport
        self._user_fns = user_fns
        self._token_store = token_store
        self._rbac = rbac_manager
        self._permissions = permission_manager

    def __call__(
        self,
        *,
        active: bool = True,
        verified: bool = False,
        scopes: list[str] | None = None,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
        fresh: bool = False,
        optional: bool = False,
    ) -> Callable:
        """Return a FastAPI dependency that resolves the current user."""

        token_service = self._token_service
        transport = self._transport
        user_fns = self._user_fns
        token_store = self._token_store
        rbac = self._rbac
        perm_mgr = self._permissions

        async def _dependency(request: Request) -> Any:
            raw_token = transport.extract_token(request)
            if raw_token is None:
                if optional:
                    return None
                raise UnauthorizedError()

            payload: TokenPayload = token_service.validate_access_token(raw_token)

            # Check revocation
            if token_store is not None:
                from urauth.tokens.revocation import RevocationService

                revocation = RevocationService(token_store)
                if await revocation.is_revoked(payload.jti):
                    raise UnauthorizedError("Token has been revoked")

            # Freshness
            if fresh and not payload.fresh:
                raise UnauthorizedError("Fresh token required")

            # Scopes
            if scopes:
                missing = set(scopes) - set(payload.scopes)
                if missing:
                    raise ForbiddenError(f"Missing scopes: {', '.join(sorted(missing))}")

            # Roles
            if roles:
                if rbac is not None:
                    if not rbac.check_roles(payload.roles, roles):
                        raise ForbiddenError("Insufficient roles")
                else:
                    if not set(roles) & set(payload.roles):
                        raise ForbiddenError("Insufficient roles")

            # Permissions
            if permissions and perm_mgr is not None:
                for perm in permissions:
                    if not perm_mgr.user_has_permission(payload.roles, perm):
                        raise ForbiddenError(f"Missing permission: {perm}")

            # Load user
            user = await user_fns.get_by_id(payload.sub)
            if user is None:
                raise UnauthorizedError("User not found")

            if active and not getattr(user, "is_active", True):
                raise UnauthorizedError("Inactive user")

            if verified and not getattr(user, "is_verified", False):
                raise ForbiddenError("Email not verified")

            return user

        return _dependency
