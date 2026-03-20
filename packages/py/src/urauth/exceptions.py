"""Core exceptions — plain Python, no framework dependency."""

from __future__ import annotations


class AuthError(Exception):
    """Base authentication/authorization error."""

    def __init__(self, detail: str = "Authentication error", *, status_code: int = 401) -> None:
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


class InvalidTokenError(AuthError):
    """Token is malformed or signature verification failed."""

    def __init__(self, detail: str = "Invalid token") -> None:
        super().__init__(detail, status_code=401)


class TokenExpiredError(AuthError):
    """Token has expired."""

    def __init__(self, detail: str = "Token has expired") -> None:
        super().__init__(detail, status_code=401)


class TokenRevokedError(AuthError):
    """Token has been revoked."""

    def __init__(self, detail: str = "Token has been revoked") -> None:
        super().__init__(detail, status_code=401)


class UnauthorizedError(AuthError):
    """User is not authenticated."""

    def __init__(self, detail: str = "Not authenticated") -> None:
        super().__init__(detail, status_code=401)


class ForbiddenError(AuthError):
    """User lacks required permissions/roles."""

    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(detail, status_code=403)
