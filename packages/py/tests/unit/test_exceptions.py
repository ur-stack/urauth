"""Tests for exception hierarchy — correct status codes and messages."""

from __future__ import annotations

from urauth.exceptions import (
    AuthError,
    ForbiddenError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UnauthorizedError,
)


class TestExceptionStatusCodes:
    def test_auth_error_is_401(self) -> None:
        err = AuthError()
        assert err.status_code == 401

    def test_invalid_token_is_401(self) -> None:
        err = InvalidTokenError()
        assert err.status_code == 401

    def test_token_expired_is_401(self) -> None:
        err = TokenExpiredError()
        assert err.status_code == 401

    def test_token_revoked_is_401(self) -> None:
        err = TokenRevokedError()
        assert err.status_code == 401

    def test_unauthorized_is_401(self) -> None:
        err = UnauthorizedError()
        assert err.status_code == 401

    def test_forbidden_is_403(self) -> None:
        err = ForbiddenError()
        assert err.status_code == 403


class TestExceptionMessages:
    def test_default_messages(self) -> None:
        assert AuthError().detail == "Authentication error"
        assert InvalidTokenError().detail == "Invalid token"
        assert TokenExpiredError().detail == "Token has expired"
        assert TokenRevokedError().detail == "Token has been revoked"
        assert UnauthorizedError().detail == "Not authenticated"
        assert ForbiddenError().detail == "Forbidden"

    def test_custom_messages(self) -> None:
        err = InvalidTokenError("bad signature")
        assert err.detail == "bad signature"
        assert str(err) == "bad signature"

    def test_auth_error_custom_status(self) -> None:
        err = AuthError("custom", status_code=429)
        assert err.status_code == 429
        assert err.detail == "custom"


class TestExceptionInheritance:
    def test_all_inherit_from_auth_error(self) -> None:
        assert issubclass(InvalidTokenError, AuthError)
        assert issubclass(TokenExpiredError, AuthError)
        assert issubclass(TokenRevokedError, AuthError)
        assert issubclass(UnauthorizedError, AuthError)
        assert issubclass(ForbiddenError, AuthError)

    def test_all_inherit_from_exception(self) -> None:
        assert issubclass(AuthError, Exception)
