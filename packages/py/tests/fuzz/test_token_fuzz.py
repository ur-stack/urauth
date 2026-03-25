"""Fuzz tests for token parsing and permission string handling.

These tests ensure that malformed inputs never cause crashes or unhandled exceptions.
Run with extended settings: make fuzz
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from urauth.authz.primitives import Permission
from urauth.config import AuthConfig
from urauth.exceptions import InvalidTokenError, TokenExpiredError
from urauth.tokens.jwt import TokenService

_CONFIG = AuthConfig(secret_key="fuzz-test-key-32-characters-long!", allow_insecure_key=True)
_SVC = TokenService(_CONFIG)


class TestDecodeTokenFuzz:
    """decode_token with arbitrary input must always raise InvalidTokenError or TokenExpiredError."""

    @given(token=st.text(min_size=0, max_size=1000))
    @settings(max_examples=500)
    def test_arbitrary_text_never_crashes(self, token: str) -> None:
        try:
            _SVC.decode_token(token)
        except (InvalidTokenError, TokenExpiredError):
            pass  # Expected
        except Exception as e:
            raise AssertionError(f"Unexpected exception type: {type(e).__name__}: {e}") from e

    @given(token=st.binary(min_size=0, max_size=500))
    @settings(max_examples=500)
    def test_arbitrary_bytes_never_crashes(self, token: bytes) -> None:
        try:
            _SVC.decode_token(token.decode("utf-8", errors="replace"))
        except (InvalidTokenError, TokenExpiredError):
            pass
        except Exception as e:
            raise AssertionError(f"Unexpected exception type: {type(e).__name__}: {e}") from e

    @given(token=st.from_regex(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", fullmatch=True))
    @settings(max_examples=300)
    def test_jwt_shaped_garbage_never_crashes(self, token: str) -> None:
        """Strings that look like JWTs (three dot-separated segments) but aren't."""
        try:
            _SVC.decode_token(token)
        except (InvalidTokenError, TokenExpiredError):
            pass
        except Exception as e:
            raise AssertionError(f"Unexpected exception type: {type(e).__name__}: {e}") from e


class TestValidateAccessTokenFuzz:
    """validate_access_token with arbitrary input must raise appropriate errors."""

    @given(token=st.text(min_size=0, max_size=500))
    @settings(max_examples=300)
    def test_arbitrary_text_rejected_safely(self, token: str) -> None:
        try:
            _SVC.validate_access_token(token)
        except (InvalidTokenError, TokenExpiredError):
            pass
        except Exception as e:
            raise AssertionError(f"Unexpected exception type: {type(e).__name__}: {e}") from e


class TestPermissionParsingFuzz:
    """Permission string parsing with arbitrary input must raise ValueError or succeed cleanly."""

    @given(text=st.text(min_size=0, max_size=200))
    @settings(max_examples=500)
    def test_arbitrary_permission_string(self, text: str) -> None:
        try:
            p = Permission(text)
            # If creation succeeds, it should be usable
            str(p)
        except (ValueError, TypeError):
            pass  # Expected for invalid input
        except Exception as e:
            raise AssertionError(f"Unexpected exception type: {type(e).__name__}: {e}") from e
