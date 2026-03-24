"""Optional middleware to pre-resolve AuthContext on each request."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from urauth.context import AuthContext

ContextResolver = Callable[[Request], Awaitable[AuthContext]]


class AccessControlMiddleware(BaseHTTPMiddleware):
    """Middleware that pre-resolves AuthContext and stores it on request.state.

    This does NOT enforce policies — it only resolves the context so that
    guard/require/check don't need to call the resolver again.

    Args:
        app: The ASGI application
        context_resolver: Async callable (Request) -> AuthContext
        exclude_paths: Paths to skip context resolution (e.g. public routes)
    """

    def __init__(
        self,
        app: object,
        context_resolver: ContextResolver,
        exclude_paths: Sequence[str] = (),
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._context_resolver = context_resolver
        self._exclude_paths = set(exclude_paths)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path not in self._exclude_paths:
            ctx = await self._context_resolver(request)
            request.state._auth_context = ctx

        return await call_next(request)
