"""Security-focused token tests — tampering, algorithm confusion, claim manipulation."""
# pyright: reportUnknownMemberType=false

from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from urauth.config import AuthConfig
from urauth.exceptions import InvalidTokenError, TokenExpiredError
from urauth.tokens.jwt import TokenService

SECRET = "test-secret-key-32-chars-long-xx"


@pytest.fixture
def svc() -> TokenService:
    return TokenService(AuthConfig(secret_key=SECRET))


class TestTokenTampering:
    def test_modified_payload_rejected(self, svc: TokenService) -> None:
        """Changing the payload without re-signing should fail verification."""
        token = svc.create_access_token("user-1")
        parts = token.split(".")
        # Tamper with payload (flip a character)
        payload_b64 = parts[1]
        tampered = payload_b64[:-1] + ("A" if payload_b64[-1] != "A" else "B")
        bad_token = f"{parts[0]}.{tampered}.{parts[2]}"
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token(bad_token)

    def test_none_algorithm_rejected(self, svc: TokenService) -> None:
        """Token signed with empty key must be rejected by service expecting real key."""
        payload = {"sub": "user-1", "jti": "x", "iat": time.time(), "exp": time.time() + 3600, "type": "access"}
        bad_token = pyjwt.encode(payload, key="", algorithm="HS256")
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token(bad_token)

    def test_wrong_secret_key_rejected(self, svc: TokenService) -> None:
        """Token from a different key must fail."""
        other = TokenService(AuthConfig(secret_key="attacker-secret-key-xxxxxxxxxxxx"))
        token = other.create_access_token("user-1")
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token(token)

    def test_empty_string_token(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token("")

    def test_garbage_bytes(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.validate_access_token("aaaa.bbbb.cccc")


class TestTokenTypeConfusion:
    def test_refresh_as_access_rejected(self, svc: TokenService) -> None:
        token = svc.create_refresh_token("user-1")
        with pytest.raises(InvalidTokenError, match="Not an access token"):
            svc.validate_access_token(token)

    def test_access_as_refresh_rejected(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1")
        with pytest.raises(InvalidTokenError, match="Not a refresh token"):
            svc.validate_refresh_token(token)


class TestTokenExpiration:
    def test_expired_access_token(self) -> None:
        svc = TokenService(AuthConfig(secret_key=SECRET, access_token_ttl=-1))
        token = svc.create_access_token("user-1")
        with pytest.raises(TokenExpiredError):
            svc.validate_access_token(token)

    def test_expired_refresh_token(self) -> None:
        svc = TokenService(AuthConfig(secret_key=SECRET, refresh_token_ttl=-1))
        token = svc.create_refresh_token("user-1")
        with pytest.raises(TokenExpiredError):
            svc.validate_refresh_token(token)


class TestIssuerAudienceValidation:
    def test_issuer_mismatch_rejected(self) -> None:
        svc_a = TokenService(AuthConfig(secret_key=SECRET, token_issuer="app-a"))
        svc_b = TokenService(AuthConfig(secret_key=SECRET, token_issuer="app-b"))
        token = svc_a.create_access_token("user-1")
        with pytest.raises(InvalidTokenError, match="issuer"):
            svc_b.validate_access_token(token)

    def test_audience_mismatch_rejected(self) -> None:
        svc_a = TokenService(AuthConfig(secret_key=SECRET, token_audience="api-a"))
        svc_b = TokenService(AuthConfig(secret_key=SECRET, token_audience="api-b"))
        token = svc_a.create_access_token("user-1")
        with pytest.raises(InvalidTokenError, match="audience"):
            svc_b.validate_access_token(token)

    def test_valid_issuer_and_audience(self) -> None:
        svc = TokenService(AuthConfig(secret_key=SECRET, token_issuer="app", token_audience="api"))
        token = svc.create_access_token("user-1")
        payload = svc.validate_access_token(token)
        assert payload.sub == "user-1"

    def test_no_audience_skip_verification(self) -> None:
        """When no audience configured, audience claim is not verified."""
        svc = TokenService(AuthConfig(secret_key=SECRET))
        token = svc.create_access_token("user-1")
        payload = svc.validate_access_token(token)
        assert payload.sub == "user-1"


class TestExtraClaimsRoundTrip:
    def test_extra_claims_preserved(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1", extra_claims={"org_id": "acme", "plan": "enterprise"})
        payload = svc.validate_access_token(token)
        assert payload.extra["org_id"] == "acme"
        assert payload.extra["plan"] == "enterprise"

    def test_standard_claims_not_in_extra(self, svc: TokenService) -> None:
        """Standard JWT claims (sub, jti, etc.) should not leak into extra."""
        token = svc.create_access_token("user-1", scopes=["read"], roles=["admin"])
        payload = svc.validate_access_token(token)
        assert "sub" not in payload.extra
        assert "jti" not in payload.extra
        assert "type" not in payload.extra
        assert "scopes" not in payload.extra
        assert "roles" not in payload.extra

    def test_empty_string_user_id(self, svc: TokenService) -> None:
        token = svc.create_access_token("")
        payload = svc.validate_access_token(token)
        assert payload.sub == ""


class TestTokenPairCreation:
    def test_pair_has_unique_jtis(self, svc: TokenService) -> None:
        pair = svc.create_token_pair("user-1")
        access_claims = svc.decode_token(pair.access_token)
        refresh_claims = svc.decode_token(pair.refresh_token)
        assert access_claims["jti"] != refresh_claims["jti"]

    def test_pair_same_user(self, svc: TokenService) -> None:
        pair = svc.create_token_pair("user-1")
        access_claims = svc.decode_token(pair.access_token)
        refresh_claims = svc.decode_token(pair.refresh_token)
        assert access_claims["sub"] == refresh_claims["sub"] == "user-1"

    def test_pair_with_family_id(self, svc: TokenService) -> None:
        pair = svc.create_token_pair("user-1", family_id="fam-1")
        refresh_claims = svc.decode_token(pair.refresh_token)
        assert refresh_claims["family_id"] == "fam-1"


class TestExtraClaimsInjection:
    """Verify that extra_claims cannot override reserved JWT claims (privilege escalation prevention)."""

    def test_extra_claims_cannot_override_sub(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1", extra_claims={"sub": "admin"})
        payload = svc.validate_access_token(token)
        assert payload.sub == "user-1"

    def test_extra_claims_cannot_override_exp(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1", extra_claims={"exp": 9999999999})
        claims = svc.decode_token(token)
        # exp should be ~now + 900 (default TTL), not the injected value
        assert claims["exp"] < time.time() + 1000

    def test_extra_claims_can_override_type_for_special_tokens(self, svc: TokenService) -> None:
        """type IS allowed in extra_claims — the library uses it for MFA/reset tokens."""
        token = svc.create_access_token("user-1", extra_claims={"type": "reset_session"})
        claims = svc.decode_token(token)
        assert claims["type"] == "reset_session"

    def test_extra_claims_cannot_override_iss(self, svc: TokenService) -> None:
        svc_with_iss = TokenService(AuthConfig(secret_key=SECRET, token_issuer="legit-app"))
        token = svc_with_iss.create_access_token("user-1", extra_claims={"iss": "evil-app"})
        claims = svc_with_iss.decode_token(token)
        assert claims["iss"] == "legit-app"

    def test_extra_claims_cannot_override_jti(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1", extra_claims={"jti": "fixed-id"})
        claims = svc.decode_token(token)
        assert claims["jti"] != "fixed-id"
