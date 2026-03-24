"""AccessControl — checker-based access control for FastAPI."""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, overload

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request

from urauth.authz.checker import PermissionChecker, StringChecker
from urauth.authz.exceptions import ConfigurationError
from urauth.authz.permission_enum import PermissionEnum
from urauth.authz.primitives import Permission
from urauth.context import AuthContext
from urauth.exceptions import ForbiddenError
from urauth.fastapi._utils import find_request_param

F = TypeVar("F", bound=Callable[..., Any])

ContextResolver = Callable[[Request], Awaitable[AuthContext]]

_BEARER_SCHEME = Depends(HTTPBearer(auto_error=False))


def _resolve_perm_args(
    resource_or_perm: str | Permission | PermissionEnum,
    action: str | None,
    caller: str,
) -> tuple[str, str, Permission | None]:
    """Parse (resource, action) or Permission into (resource, action, perm_obj)."""
    if isinstance(resource_or_perm, PermissionEnum):
        perm = resource_or_perm.value
        return str(perm.resource), str(perm.action), perm
    if isinstance(resource_or_perm, Permission):
        return str(resource_or_perm.resource), str(resource_or_perm.action), resource_or_perm
    if action is None:
        raise ConfigurationError(f"{caller}() requires (resource, action) or a Permission object")
    return resource_or_perm, action, None


class _Guard:
    """Dual-use object: works as both a decorator and a FastAPI dependency."""

    def __init__(
        self,
        access: AccessControl,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        scope_from: str | None = None,
        permission: Permission | None = None,
    ) -> None:
        self._access = access
        self._resource = resource
        self._action = action
        self._scope = scope
        self._scope_from = scope_from
        self._permission = permission
        self.__signature__ = inspect.Signature(
            [
                inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
                inspect.Parameter(
                    "_credentials",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=_BEARER_SCHEME,
                    annotation=HTTPAuthorizationCredentials | None,
                ),
            ]
        )

    def __call__(self, func_or_request: Any = None, /, **kwargs: Any) -> Any:
        if func_or_request is not None and callable(func_or_request) and not isinstance(func_or_request, Request):
            return self._wrap(func_or_request)
        request: Request = func_or_request or kwargs.get("request")  # type: ignore[assignment]
        return self._execute_dependency(request)

    def _resolve_scope(self, request: Request, kwargs: dict[str, Any] | None = None) -> str | None:
        if self._scope_from is not None:
            if kwargs:
                return kwargs.get(self._scope_from) or request.path_params.get(self._scope_from)
            return request.path_params.get(self._scope_from)
        return self._scope

    async def _check_and_deny(self, request: Request, scope: str | None) -> bool:
        allowed = await self._access.evaluate(
            request,
            self._resource,
            self._action,
            scope=scope,
            permission=self._permission,
        )
        if not allowed:
            if self._access.on_deny:
                self._access.on_deny()
            if self._access.auto_error:
                raise ForbiddenError()
            return False
        return True

    async def _execute_dependency(self, request: Request) -> bool:
        return await self._check_and_deny(request, self._resolve_scope(request))

    def _wrap(self, func: F) -> F:
        request_param = find_request_param(func)
        if request_param is None:
            raise ConfigurationError(
                f"Endpoint '{func.__name__}' must have a 'request: Request' parameter "
                f"to use the @access.guard() decorator."
            )

        sig = inspect.signature(func)
        guard = self

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            kwargs.pop("_credentials", None)

            request = kwargs.get(request_param)
            if request is None:
                param_names = list(sig.parameters.keys())
                idx = param_names.index(request_param)  # type: ignore[arg-type]
                if idx < len(args):
                    request = args[idx]

            if request is None:
                raise ConfigurationError(f"Could not extract Request from endpoint '{func.__name__}'")

            scope = guard._resolve_scope(request, kwargs)
            await guard._check_and_deny(request, scope)

            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        params = list(sig.parameters.values())
        if "_credentials" not in sig.parameters:
            params.append(
                inspect.Parameter(
                    "_credentials",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=_BEARER_SCHEME,
                    annotation=HTTPAuthorizationCredentials | None,
                )
            )
        wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]


# Mark __call__ as async-compatible for FastAPI/Starlette dependency detection.
if hasattr(inspect, "markcoroutinefunction"):
    inspect.markcoroutinefunction(_Guard.__call__)  # type: ignore[attr-defined]
else:
    _Guard.__call__._is_coroutine = asyncio.coroutines._is_coroutine  # type: ignore[attr-defined]


class AccessControl:
    """Checker-based access control for FastAPI.

    Usage patterns::

        @access.guard("task", "read")           # Decorator (resource, action)
        @access.guard(Perms.TASK_READ)           # Decorator (typed)
        Depends(access.guard(...))               # Dependency
        await access.check("task", "read", request=...)  # Inline bool
    """

    def __init__(
        self,
        context_resolver: ContextResolver,
        checker: PermissionChecker | None = None,
        *,
        on_deny: Callable[..., Any] | None = None,
        auto_error: bool = True,
    ) -> None:
        self._checker: PermissionChecker = checker or StringChecker()
        self._context_resolver = context_resolver
        self.on_deny = on_deny
        self.auto_error = auto_error

    async def _resolve_context(self, request: Request) -> AuthContext:
        cached = getattr(request.state, "_auth_context", None)
        if cached is not None:
            return cached
        ctx = await self._context_resolver(request)
        request.state._auth_context = ctx
        return ctx

    async def evaluate(
        self,
        request: Request,
        resource: str,
        action: str,
        *,
        scope: str | None = None,
        permission: Permission | None = None,
    ) -> bool:
        ctx = await self._resolve_context(request)
        extra: dict[str, Any] = {}
        if permission is not None:
            extra["permission"] = permission
        return await self._checker.has_permission(ctx, resource, action, scope=scope, **extra)

    @overload
    def guard(
        self,
        resource_or_perm: Permission | PermissionEnum,
        *,
        scope: str | None = ...,
        scope_from: str | None = ...,
    ) -> _Guard: ...

    @overload
    def guard(
        self,
        resource_or_perm: str,
        action: str,
        *,
        scope: str | None = ...,
        scope_from: str | None = ...,
    ) -> _Guard: ...

    def guard(
        self,
        resource_or_perm: str | Permission | PermissionEnum,
        action: str | None = None,
        *,
        scope: str | None = None,
        scope_from: str | None = None,
    ) -> _Guard:
        resource, action_str, perm_obj = _resolve_perm_args(resource_or_perm, action, "guard")
        return _Guard(self, resource, action_str, scope=scope, scope_from=scope_from, permission=perm_obj)

    @overload
    async def check(
        self,
        resource_or_perm: Permission | PermissionEnum,
        *,
        scope: str | None = ...,
        request: Request,
    ) -> bool: ...

    @overload
    async def check(
        self,
        resource_or_perm: str,
        action: str,
        *,
        scope: str | None = ...,
        request: Request,
    ) -> bool: ...

    async def check(
        self,
        resource_or_perm: str | Permission | PermissionEnum,
        action: str | None = None,
        *,
        scope: str | None = None,
        request: Request,
    ) -> bool:
        """Inline check. Returns bool, never raises."""
        resource, action_str, perm_obj = _resolve_perm_args(resource_or_perm, action, "check")
        return await self.evaluate(request, resource, action_str, scope=scope, permission=perm_obj)
