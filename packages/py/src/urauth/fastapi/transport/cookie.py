from __future__ import annotations

from typing import Literal

from fastapi import Request, Response

from urauth.config import AuthConfig


class RefreshCookieManager:
    """Manages the httpOnly refresh token cookie.

    Refresh tokens are always stored httpOnly (inaccessible to JS) to prevent
    XSS-based token theft. SameSite=strict prevents CSRF on the refresh endpoint.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._name = config.refresh_cookie_name
        self._secure = config.refresh_cookie_secure
        self._samesite: Literal["lax", "strict", "none"] = config.refresh_cookie_samesite
        self._max_age = config.refresh_cookie_max_age or config.refresh_token_ttl
        self._domain = config.refresh_cookie_domain
        self._path = config.refresh_cookie_path

    def extract_token(self, request: Request) -> str | None:
        return request.cookies.get(self._name)

    def set_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self._name,
            value=token,
            max_age=self._max_age,
            httponly=True,
            secure=self._secure,
            samesite=self._samesite,
            domain=self._domain,
            path=self._path,
        )

    def delete_token(self, response: Response) -> None:
        response.delete_cookie(
            key=self._name,
            domain=self._domain,
            path=self._path,
        )


class CookieTransport:
    """Extract/set tokens via HTTP-only cookies."""

    def __init__(self, config: AuthConfig) -> None:
        self._name = config.cookie_name
        self._secure = config.cookie_secure
        self._httponly = config.cookie_httponly
        self._samesite: Literal["lax", "strict", "none"] = config.cookie_samesite
        self._max_age = config.cookie_max_age or config.access_token_ttl
        self._domain = config.cookie_domain
        self._path = config.cookie_path

    def extract_token(self, request: Request) -> str | None:
        return request.cookies.get(self._name)

    def set_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self._name,
            value=token,
            max_age=self._max_age,
            httponly=self._httponly,
            secure=self._secure,
            samesite=self._samesite,
            domain=self._domain,
            path=self._path,
        )

    def delete_token(self, response: Response) -> None:
        response.delete_cookie(
            key=self._name,
            domain=self._domain,
            path=self._path,
        )
