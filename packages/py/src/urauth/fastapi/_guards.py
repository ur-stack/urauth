"""Consolidated dual-use guard classes for FastAPI.

All guards work as both ``@decorator`` and ``Depends(guard)``::

    # Decorator
    @auth.require(can_read)
    async def endpoint(request: Request): ...

    # Dependency
    @app.get("/x", dependencies=[Depends(auth.require(can_read))])
    async def endpoint(): ...
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from abc import abstractmethod
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request

from urauth.auth import Auth, maybe_await
from urauth.context import AuthContext
from urauth.exceptions import ForbiddenError, UnauthorizedError
from urauth.fastapi._utils import find_context_and_request, find_request_param

F = TypeVar("F", bound=Callable[..., Any])

ContextResolver = Callable[[Request], Awaitable[AuthContext]]

_BEARER_SCHEME = Depends(HTTPBearer(auto_error=False))


class _BaseGuard:
    """Base dual-use guard: works as both @decorator and Depends().

    Subclasses implement ``_check(ctx, request)`` with their specific logic.
    """

    def __init__(self, resolve_context: ContextResolver) -> None:
        self._resolve_context = resolve_context
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
        return self._execute(request)

    async def _execute(self, request: Request) -> bool:
        """Dependency mode — resolve context and check."""
        ctx = await self._resolve_context(request)
        if not ctx.is_authenticated():
            raise UnauthorizedError()
        await self._check(ctx, request)
        return True

    @abstractmethod
    async def _check(self, ctx: AuthContext, request: Request) -> None:
        """Subclass hook — raise ForbiddenError if check fails."""
        ...

    def _wrap(self, func: F) -> F:
        """Decorator mode — wrap an endpoint function."""
        resolve_context = self._resolve_context
        guard = self
        request_param = find_request_param(func)
        sig = inspect.signature(func)

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            kwargs.pop("_credentials", None)  # Consumed by FastAPI for OpenAPI schema only
            ctx, request = find_context_and_request(sig, request_param, args, kwargs)

            if ctx is None and request is not None:
                ctx = await resolve_context(request)

            if ctx is None:
                raise UnauthorizedError()
            if not ctx.is_authenticated():
                raise UnauthorizedError()

            await guard._check(ctx, request)  # type: ignore[arg-type]

            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        # Inject HTTPBearer into signature so Swagger shows the lock icon
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
# Python 3.12+ has inspect.markcoroutinefunction; fall back to _is_coroutine for 3.10-3.11.
if hasattr(inspect, "markcoroutinefunction"):
    inspect.markcoroutinefunction(_BaseGuard.__call__)  # type: ignore[attr-defined]
else:
    _BaseGuard.__call__._is_coroutine = asyncio.coroutines._is_coroutine  # type: ignore[attr-defined]


class RequirementGuard(_BaseGuard):
    """Guard for composable Requirement checks (Permission, Role, AllOf, AnyOf)."""

    def __init__(self, resolve_context: ContextResolver, requirement: Any) -> None:
        super().__init__(resolve_context)
        self._requirement = requirement

    async def _check(self, ctx: AuthContext, request: Request) -> None:
        if not ctx.satisfies(self._requirement):
            raise ForbiddenError()


class RelationGuard(_BaseGuard):
    """Guard for Zanzibar-style relation checks."""

    def __init__(
        self,
        resolve_context: ContextResolver,
        auth: Auth,
        relation: Any,
        resource_id_from: str,
    ) -> None:
        super().__init__(resolve_context)
        self._auth = auth
        self._relation = relation
        self._resource_id_from = resource_id_from

    async def _check(self, ctx: AuthContext, request: Request) -> None:
        resource_id = request.path_params.get(self._resource_id_from)
        if resource_id is None:
            raise ForbiddenError(f"Missing resource ID: {self._resource_id_from}")
        has_rel = await maybe_await(self._auth.check_relation(ctx.user, self._relation, str(resource_id)))
        if not has_rel:
            raise ForbiddenError()


class PolicyGuard(_BaseGuard):
    """Guard with arbitrary policy logic."""

    def __init__(
        self,
        resolve_context: ContextResolver,
        check: Callable[[AuthContext], bool] | Callable[[AuthContext], Any],
    ) -> None:
        super().__init__(resolve_context)
        self._policy_check = check

    async def _check(self, ctx: AuthContext, request: Request) -> None:
        result = self._policy_check(ctx)
        if inspect.isawaitable(result):
            result = await result
        if not result:
            raise ForbiddenError()
