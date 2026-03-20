"""Tests for TokenService — create/validate JWT tokens."""

from __future__ import annotations

import pytest

from urauth.config import AuthConfig
from urauth.exceptions import InvalidTokenError, TokenExpiredError
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPair


@pytest.fixture
def svc() -> TokenService:
    return TokenService(AuthConfig(secret_key="test-secret"))


class TestCreateAccessToken:
    def test_basic(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_with_claims(self, svc: TokenService) -> None:
        token = svc.create_access_token(
            "user-1",
            scopes=["read", "write"],
            roles=["admin"],
            tenant_id="t-1",
            fresh=True,
            extra_claims={"custom": "value"},
        )
        payload = svc.validate_access_token(token)
        assert payload.sub == "user-1"
        assert payload.scopes == ["read", "write"]
        assert payload.roles == ["admin"]
        assert payload.tenant_id == "t-1"
        assert payload.fresh is True
        assert payload.extra["custom"] == "value"


class TestCreateRefreshToken:
    def test_basic(self, svc: TokenService) -> None:
        token = svc.create_refresh_token("user-1")
        claims = svc.validate_refresh_token(token)
        assert claims["sub"] == "user-1"
        assert claims["type"] == "refresh"

    def test_with_family(self, svc: TokenService) -> None:
        token = svc.create_refresh_token("user-1", family_id="fam-1")
        claims = svc.validate_refresh_token(token)
        assert claims["family_id"] == "fam-1"


class TestCreateTokenPair:
    def test_returns_pair(self, svc: TokenService) -> None:
        pair = svc.create_token_pair("user-1")
        assert isinstance(pair, TokenPair)
        assert pair.token_type == "bearer"

        # Both should be valid
        access = svc.validate_access_token(pair.access_token)
        refresh = svc.validate_refresh_token(pair.refresh_token)
        assert access.sub == "user-1"
        assert refresh["sub"] == "user-1"


class TestValidation:
    def test_expired_token(self) -> None:
        svc = TokenService(AuthConfig(secret_key="test", access_token_ttl=-1))
        token = svc.create_access_token("user-1")
        with pytest.raises(TokenExpiredError):
            svc.validate_access_token(token)

    def test_invalid_signature(self, svc: TokenService) -> None:
        other = TokenService(AuthConfig(secret_key="different-key"))
        token = other.create_access_token("user-1")
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token(token)

    def test_refresh_token_rejected_as_access(self, svc: TokenService) -> None:
        token = svc.create_refresh_token("user-1")
        with pytest.raises(InvalidTokenError, match="Not an access token"):
            svc.validate_access_token(token)

    def test_access_token_rejected_as_refresh(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1")
        with pytest.raises(InvalidTokenError, match="Not a refresh token"):
            svc.validate_refresh_token(token)

    def test_issuer_validation(self) -> None:
        svc = TokenService(AuthConfig(secret_key="test", token_issuer="my-app"))
        token = svc.create_access_token("user-1")
        payload = svc.validate_access_token(token)
        assert payload.sub == "user-1"

        # Token from different issuer
        other = TokenService(AuthConfig(secret_key="test", token_issuer="other-app"))
        token2 = other.create_access_token("user-1")
        with pytest.raises(InvalidTokenError, match="Invalid issuer"):
            svc.validate_access_token(token2)

    def test_garbage_token(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token("not.a.token")
