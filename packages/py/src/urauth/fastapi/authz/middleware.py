"""Optional middleware to pre-resolve Subject on each request."""

from __future__ import annotations

import inspect
from collections.abc import Sequence

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .types import SubjectResolver


class AccessControlMiddleware(BaseHTTPMiddleware):
    """Middleware that pre-resolves the Subject and stores it on request.state.

    This does NOT enforce policies — it only resolves the subject so that
    guard/require/check don't need to call the resolver again.

    Args:
        app: The ASGI application
        subject_resolver: Async or sync callable (Request) -> Subject
        exclude_paths: Paths to skip subject resolution (e.g. public routes)
    """

    def __init__(
        self,
        app: object,
        subject_resolver: SubjectResolver,
        exclude_paths: Sequence[str] = (),
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._subject_resolver = subject_resolver
        self._exclude_paths = set(exclude_paths)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path not in self._exclude_paths:
            result = self._subject_resolver(request)
            if inspect.isawaitable(result):
                result = await result
            request.state.subject = result

        return await call_next(request)
