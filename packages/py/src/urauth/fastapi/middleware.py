"""CSRF and token refresh middleware."""

from __future__ import annotations

import hmac
import secrets
import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from urauth.config import AuthConfig


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection.

    On safe methods (GET, HEAD, OPTIONS): sets a CSRF cookie if not present.
    On unsafe methods: validates that the header matches the cookie.
    """

    def __init__(self, app: Any, config: AuthConfig) -> None:
        super().__init__(app)
        self._cookie_name = config.csrf_cookie_name
        self._header_name = config.csrf_header_name

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response = await call_next(request)
            if self._cookie_name not in request.cookies:
                token = secrets.token_urlsafe(32)
                response.set_cookie(
                    key=self._cookie_name,
                    value=token,
                    httponly=False,  # JS needs to read it
                    samesite="lax",
                    secure=True,
                )
            return response

        # Unsafe method: validate CSRF
        cookie_token = request.cookies.get(self._cookie_name)
        header_token = request.headers.get(self._header_name)

        if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
            return Response(content="CSRF validation failed", status_code=403)

        return await call_next(request)


class TokenRefreshMiddleware(BaseHTTPMiddleware):
    """Automatically refresh near-expiry access tokens in cookies.

    If the access token in the cookie will expire within ``threshold``
    seconds, a new token is issued and set on the response.
    """

    def __init__(
        self,
        app: Any,
        token_service: Any,
        transport: Any,
        threshold: int = 300,
    ) -> None:
        super().__init__(app)
        self._token_service = token_service
        self._transport = transport
        self._threshold = threshold

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        raw_token = self._transport.extract_token(request)
        if raw_token is None:
            return response

        try:
            claims = self._token_service.decode_token(raw_token)
            remaining = claims.get("exp", 0) - time.time()
            if 0 < remaining < self._threshold:
                new_token = self._token_service.create_access_token(
                    claims["sub"],
                    scopes=claims.get("scopes"),
                    roles=claims.get("roles"),
                    tenant_id=claims.get("tenant_id"),
                )
                self._transport.set_token(response, new_token)
        except Exception:
            pass

        return response
