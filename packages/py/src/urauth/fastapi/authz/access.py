"""Main AccessControl class providing guard(), require(), and check()."""

from __future__ import annotations

import functools
import inspect
import typing
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from starlette.requests import Request

from urauth.authz.context import AccessContext
from urauth.authz.exceptions import AccessDeniedError, ConfigurationError
from urauth.authz.policy.base import Policy
from urauth.authz.subject import Subject
from urauth.authz.types import PermissionT, ResourceT, RoleT
from urauth.fastapi.authz.types import SubjectResolver

F = TypeVar("F", bound=Callable[..., Any])


class AccessControl(Generic[RoleT, PermissionT, ResourceT]):
    """Main access control class providing three usage patterns.

    - guard(): Decorator that enforces policy before endpoint execution
    - require(): Dependency for use with FastAPI's Depends()
    - check(): Inline boolean check, never raises

    Args:
        policy: The policy (or combined policies) to enforce
        subject_resolver: Async or sync callable (Request) -> Subject
        on_deny: Optional callback invoked on access denial
        auto_error: If True (default), raise AccessDeniedError on denial
    """

    def __init__(
        self,
        policy: Policy,
        subject_resolver: SubjectResolver,
        *,
        on_deny: Callable[..., Any] | None = None,
        auto_error: bool = True,
    ) -> None:
        self._policy = policy
        self._subject_resolver = subject_resolver
        self._on_deny = on_deny
        self._auto_error = auto_error

    async def _resolve_subject(self, request: Request) -> Subject:
        """Resolve subject from request, supporting sync/async resolvers."""
        # Check if subject was pre-resolved by middleware
        subject = getattr(request.state, "subject", None)
        if subject is not None:
            return subject

        result = self._subject_resolver(request)
        if inspect.isawaitable(result):
            result = await result
        return result  # type: ignore[return-value]

    async def _evaluate(
        self,
        request: Request,
        action: str | None,
        resource: str | None,
    ) -> bool:
        """Core evaluation logic."""
        subject = await self._resolve_subject(request)
        context = AccessContext(
            subject=subject,
            action=str(action) if action is not None else None,
            resource=str(resource) if resource is not None else None,
        )
        return await self._policy.evaluate(context)

    def guard(
        self,
        action: PermissionT | None = None,
        *,
        resource: ResourceT | None = None,
    ) -> Callable[[F], F]:
        """Decorator that enforces the policy before endpoint execution.

        The decorated endpoint must have a `request: Request` parameter.
        """

        def decorator(func: F) -> F:
            # Find the Request parameter name
            # Use get_type_hints to resolve string annotations from __future__
            try:
                hints = typing.get_type_hints(func)
            except Exception:
                hints = {}
            sig = inspect.signature(func)
            request_param: str | None = None
            for name in sig.parameters:
                hint = hints.get(name, sig.parameters[name].annotation)
                if hint is Request or (
                    isinstance(hint, type) and issubclass(hint, Request)
                ):
                    request_param = name
                    break
                # Also check string annotation as fallback
                if isinstance(hint, str) and hint in ("Request", "starlette.requests.Request"):
                    request_param = name
                    break

            if request_param is None:
                raise ConfigurationError(
                    f"Endpoint '{func.__name__}' must have a 'request: Request' parameter "
                    f"to use the @access.guard() decorator."
                )

            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                request = kwargs.get(request_param)
                if request is None:
                    # Try positional args
                    param_names = list(sig.parameters.keys())
                    idx = param_names.index(request_param)  # type: ignore[arg-type]
                    if idx < len(args):
                        request = args[idx]

                if request is None:
                    raise ConfigurationError(
                        f"Could not extract Request from endpoint '{func.__name__}'"
                    )

                allowed = await self._evaluate(request, action, resource)
                if not allowed:
                    if self._on_deny:
                        self._on_deny()
                    if self._auto_error:
                        raise AccessDeniedError()
                    return None

                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)

            # Preserve the original signature for FastAPI
            wrapper.__signature__ = sig  # type: ignore[attr-defined]
            return wrapper  # type: ignore[return-value]

        return decorator

    def require(
        self,
        action: PermissionT | None = None,
        *,
        resource: ResourceT | None = None,
    ) -> Any:
        """Return an async dependency for use with FastAPI's Depends().

        Usage:
            @app.get("/docs")
            async def list_docs(allowed: bool = Depends(access.require(Perm.READ))):
                ...
        """

        async def _dependency(request: Request) -> bool:
            allowed = await self._evaluate(request, action, resource)
            if not allowed:
                if self._on_deny:
                    self._on_deny()
                if self._auto_error:
                    raise AccessDeniedError()
                return False
            return True

        return _dependency

    async def check(
        self,
        action: PermissionT | None = None,
        *,
        resource: ResourceT | None = None,
        request: Request,
    ) -> bool:
        """Inline check. Returns bool, never raises."""
        return await self._evaluate(request, action, resource)
