"""FastAPI rate limiting adapter — Depends() and middleware integration.

Usage::

    from pyrate_limiter import Duration, Rate
    from urauth.ratelimit import KeyStrategy
    from urauth.fastapi.ratelimit import RateLimit

    # IP-based (default)
    ip_limit = RateLimit(rates=[Rate(100, Duration.MINUTE)])

    # User-identity-based (extracts user from JWT/AuthContext)
    user_limit = RateLimit(
        rates=[Rate(20, Duration.MINUTE)],
        key=KeyStrategy.IDENTITY,
        auth=auth,  # urauth.Auth instance for JWT decoding
    )

    # Session-based
    session_limit = RateLimit(
        rates=[Rate(50, Duration.MINUTE)],
        key=KeyStrategy.SESSION,
    )

    # As dependency
    @app.get("/api/data", dependencies=[Depends(ip_limit)])
    async def get_data(): ...

    # As decorator
    @app.get("/api/data")
    @ip_limit
    async def get_data(request: Request): ...

    # Combined limits
    @app.get("/api/data", dependencies=[Depends(ip_limit), Depends(user_limit)])
    async def get_data(): ...
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import HTTPException
from starlette.requests import Request

from urauth.fastapi._utils import find_request_param
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.ratelimit import KeyStrategy, RateLimiter

F = TypeVar("F", bound=Callable[..., Any])


class RateLimit:
    """FastAPI-compatible rate limit guard.

    Works as both a ``Depends()`` dependency and a decorator.
    Raises HTTP 429 when rate limit is exceeded.
    """

    def __init__(
        self,
        rates: list[Any],
        *,
        key: KeyStrategy | str = KeyStrategy.IP,
        key_func: Callable[..., str] | None = None,
        bucket: Any | None = None,
        prefix: str = "rl",
        auth: Any | None = None,
        status_code: int = 429,
        detail: str = "Rate limit exceeded",
    ) -> None:
        """
        Args:
            rates: List of ``pyrate_limiter.Rate`` objects.
            key: Key strategy (IP, IDENTITY, SESSION, JWT).
            key_func: Custom key function ``(request: Request) -> str``.
            bucket: Custom bucket backend (e.g. RedisBucket).
            prefix: Key prefix for namespacing.
            auth: Optional ``Auth`` instance for extracting user/JWT info.
            status_code: HTTP status code on rate limit (default 429).
            detail: Error message on rate limit.
        """
        self._limiter = RateLimiter(
            rates=rates,
            key=key,
            prefix=prefix,
            bucket=bucket,
        )
        self._key_strategy = key
        self._custom_key_func = key_func
        self._auth = auth
        self._status_code = status_code
        self._detail = detail

        # Set signature so FastAPI knows to inject Request
        self.__signature__ = inspect.Signature(
            [
                inspect.Parameter(
                    "request",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Request,
                ),
            ]
        )

    def __call__(self, func_or_request: Any = None, /, **kwargs: Any) -> Any:
        # Decorator mode: called with a function
        if func_or_request is not None and callable(func_or_request) and not isinstance(func_or_request, Request):
            return self._wrap(func_or_request)
        # Dependency mode: called with Request by FastAPI
        request: Request = func_or_request or kwargs.get("request")  # type: ignore[assignment]
        return self._execute(request)

    async def _extract_key(self, request: Request) -> str:
        """Extract rate limit key from the request."""
        if self._custom_key_func is not None:
            result = self._custom_key_func(request)
            if inspect.isawaitable(result):
                result = await result
            return result

        ip = request.client.host if request.client else None
        user_id: str | None = None
        session_id: str | None = None
        jwt_sub: str | None = None

        # Try to get user info from cached AuthContext
        ctx = getattr(request.state, "_auth_context", None)
        if ctx is not None and ctx.is_authenticated():
            user_id = str(getattr(ctx.user, "id", None))
            if ctx.token is not None:
                jwt_sub = ctx.token.sub

        # Try to get session from cookies
        if self._key_strategy == KeyStrategy.SESSION:
            config = self._auth.config if self._auth else None
            cookie_name = getattr(config, "session_cookie_name", "session_id")
            session_id = request.cookies.get(cookie_name)

        # For JWT strategy, try to decode token if no cached context
        if self._key_strategy == KeyStrategy.JWT and jwt_sub is None and self._auth is not None:
            try:
                transport = BearerTransport()
                raw_token = transport.extract_token(request)
                if raw_token:
                    payload = self._auth.token_service.validate_access_token(raw_token)
                    jwt_sub = payload.sub
            except Exception:
                pass

        return self._limiter.resolve_key(
            ip=ip,
            user_id=user_id,
            session_id=session_id,
            jwt_sub=jwt_sub,
        )

    async def _execute(self, request: Request) -> bool:
        """Dependency mode — check rate limit and raise 429 if exceeded."""
        key = await self._extract_key(request)
        allowed = await self._limiter.check(key)
        if not allowed:
            raise HTTPException(
                status_code=self._status_code,
                detail=self._detail,
            )
        return True

    def _wrap(self, func: F) -> F:
        """Decorator mode — wrap an endpoint function."""
        request_param = find_request_param(func)
        sig = inspect.signature(func)
        rate_limit = self

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find request
            request: Request | None = None
            if request_param is not None:
                request = kwargs.get(request_param)
                if request is None:
                    param_names = list(sig.parameters.keys())
                    try:
                        idx = param_names.index(request_param)
                        if idx < len(args):
                            request = args[idx]
                    except ValueError:
                        pass

            if request is None:
                for v in kwargs.values():
                    if isinstance(v, Request):
                        request = v  # type: ignore[reportUnknownVariableType]
                        break

            if request is not None:
                key = await rate_limit._extract_key(request)
                allowed = await rate_limit._limiter.check(key)
                if not allowed:
                    raise HTTPException(
                        status_code=rate_limit._status_code,
                        detail=rate_limit._detail,
                    )

            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        wrapper.__signature__ = sig  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]


# Mark __call__ as async-compatible for FastAPI
RateLimit.__call__._is_coroutine = asyncio.coroutines._is_coroutine  # type: ignore[attr-defined]
