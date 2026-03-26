"""Security tests for malformed and adversarial inputs.

Validates that the token service and authorization primitives handle
garbage, oversized, and crafted inputs without crashing or leaking data.
"""

from __future__ import annotations

import base64
import json

import jwt as pyjwt
import pytest

from urauth.authz.primitives import Permission, Relation, RelationTuple
from urauth.config import AuthConfig
from urauth.exceptions import InvalidTokenError, TokenExpiredError
from urauth.tokens.jwt import TokenService

SECRET = "test-secret-key-32-chars-long-xx"


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(
        secret_key=SECRET,
        environment="testing",
    )


@pytest.fixture
def svc(config: AuthConfig) -> TokenService:
    return TokenService(config)


class TestExtremelyLongTokenStrings:
    """Extremely long tokens should be rejected cleanly, not cause DoS."""

    def test_10kb_random_token(self, svc: TokenService) -> None:
        long_token = "a" * 10_000
        with pytest.raises(InvalidTokenError):
            svc.decode_token(long_token)

    def test_100kb_random_token(self, svc: TokenService) -> None:
        long_token = "x" * 100_000
        with pytest.raises(InvalidTokenError):
            svc.decode_token(long_token)

    def test_long_token_with_dots(self, svc: TokenService) -> None:
        long_token = "a" * 3000 + "." + "b" * 3000 + "." + "c" * 3000
        with pytest.raises(InvalidTokenError):
            svc.decode_token(long_token)


class TestTokenWithNullBytes:
    """Null bytes in token strings must not cause undefined behavior."""

    def test_null_bytes_in_token(self, svc: TokenService) -> None:
        with pytest.raises((InvalidTokenError, ValueError)):
            svc.decode_token("eyJ\x00abc.def.ghi")

    def test_null_bytes_between_segments(self, svc: TokenService) -> None:
        with pytest.raises((InvalidTokenError, ValueError)):
            svc.decode_token("eyJ0eXAiOiJ\x00.eyJ0ZXN0Ijo\x00.sig")


class TestTokenWithUnicode:
    """Unicode characters in token strings must be handled safely."""

    def test_emoji_token(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("\U0001f4a9.\U0001f525.\U0001f680")

    def test_rtl_characters(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("\u202e\u0645\u0631\u062d\u0628\u0627.test.sig")

    def test_zero_width_characters(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("\u200b.\u200b.\u200b")


class TestTokenStructuralAnomalies:
    """Structurally malformed tokens must fail with clear errors."""

    def test_only_dots(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token(".....")

    def test_three_dots(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("...")

    def test_extra_segments(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("a.b.c.d")

    def test_empty_segments(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("..")

    def test_empty_string(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("")

    def test_single_segment(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("abcdef")

    def test_two_segments(self, svc: TokenService) -> None:
        with pytest.raises(InvalidTokenError):
            svc.decode_token("abc.def")


class TestAlgorithmConfusion:
    """Token claiming a different algorithm than the one configured."""

    def test_header_claims_none_algorithm(self, svc: TokenService) -> None:
        """A token crafted with alg:none must be rejected."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "attacker", "type": "access", "jti": "x", "iat": 0, "exp": 9999999999}).encode()
        ).rstrip(b"=")
        crafted = header.decode() + "." + payload.decode() + "."
        with pytest.raises(InvalidTokenError):
            svc.decode_token(crafted)

    def test_header_claims_different_hmac(self, svc: TokenService, config: AuthConfig) -> None:
        """A token signed with HS384 but config expects HS256 must be rejected."""
        token = pyjwt.encode(
            {"sub": "attacker", "type": "access", "jti": "x", "iat": 0, "exp": 9999999999},
            config.secret_key,
            algorithm="HS384",
        )
        with pytest.raises(InvalidTokenError):
            svc.decode_token(token)

    def test_header_claims_rs256_with_hmac_key(self, svc: TokenService) -> None:
        """A token header claiming RS256 but using HMAC key material must fail."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "attacker", "type": "access"}).encode()
        ).rstrip(b"=")
        crafted = header.decode() + "." + payload.decode() + ".fakesig"
        with pytest.raises(InvalidTokenError):
            svc.decode_token(crafted)


class TestDuplicateClaimsInPayload:
    """Hand-crafted tokens with duplicate JSON keys in payload."""

    def test_duplicate_sub_claim(self, svc: TokenService, config: AuthConfig) -> None:
        """JSON with duplicate 'sub' key -- last value wins in Python json.loads.
        The important thing is this doesn't crash or bypass validation."""
        # Build a token where the payload JSON has duplicate 'sub' keys.
        # Python's json.loads takes the last value, so this tests that
        # the decode path handles it predictably.
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        # Manually construct JSON with duplicate keys
        raw_payload = '{"sub":"user1","sub":"attacker","type":"access","jti":"x","iat":0,"exp":9999999999}'
        payload = base64.urlsafe_b64encode(raw_payload.encode()).rstrip(b"=")
        # Sign it properly
        signing_input = header.decode() + "." + payload.decode()
        import hmac
        import hashlib
        sig = base64.urlsafe_b64encode(
            hmac.new(config.secret_key.encode(), signing_input.encode(), hashlib.sha256).digest()
        ).rstrip(b"=")
        crafted = signing_input + "." + sig.decode()
        # Should either decode successfully (with last 'sub' value) or reject
        try:
            claims = svc.decode_token(crafted)
            # If it succeeds, Python json.loads took the last 'sub' value
            assert claims["sub"] == "attacker"
        except InvalidTokenError:
            pass  # Also acceptable


class TestExtremelyLongUserId:
    """Very long user_id should either work or fail cleanly."""

    def test_long_user_id_creates_token(self, svc: TokenService) -> None:
        long_id = "u" * 10_000
        # Should succeed -- no length limit on user_id in JWT
        token = svc.create_access_token(long_id)
        payload = svc.validate_access_token(token)
        assert payload.sub == long_id

    def test_extremely_long_user_id(self, svc: TokenService) -> None:
        huge_id = "x" * 100_000
        # Should succeed or fail cleanly (not crash)
        try:
            token = svc.create_access_token(huge_id)
            payload = svc.validate_access_token(token)
            assert payload.sub == huge_id
        except (ValueError, OverflowError, MemoryError):
            pass  # Acceptable failure modes


class TestPermissionStringAdversarialInputs:
    """Permission primitives must handle adversarial string inputs."""

    def test_permission_with_null_byte(self) -> None:
        """Null byte in permission string should be handled."""
        # The separator detection may or may not match \x00.
        # The key thing is it doesn't crash or cause undefined behavior.
        try:
            p = Permission("user\x00:read")
            assert p.resource is not None
        except ValueError:
            pass  # Also acceptable

    def test_permission_with_unicode(self) -> None:
        p = Permission("\U0001f4a9:\U0001f525")
        assert str(p.resource) == "\U0001f4a9"
        assert str(p.action) == "\U0001f525"

    def test_extremely_long_permission_string(self) -> None:
        long_resource = "r" * 10_000
        long_action = "a" * 10_000
        p = Permission(f"{long_resource}:{long_action}")
        assert str(p.resource) == long_resource
        assert str(p.action) == long_action

    def test_permission_with_multiple_separators(self) -> None:
        """Only the first separator is used for splitting."""
        p = Permission("user:read:write")
        assert str(p.resource) == "user"
        assert str(p.action) == "read:write"

    def test_permission_empty_resource(self) -> None:
        p = Permission(":read")
        assert str(p.resource) == ""
        assert str(p.action) == "read"

    def test_permission_empty_action(self) -> None:
        p = Permission("user:")
        assert str(p.resource) == "user"
        assert str(p.action) == ""


class TestRelationTupleParsingMalformedInput:
    """RelationTuple.parse must handle garbage input safely."""

    def test_empty_string(self) -> None:
        with pytest.raises((ValueError, IndexError)):
            RelationTuple.parse("")

    def test_no_colon(self) -> None:
        with pytest.raises((ValueError, IndexError)):
            RelationTuple.parse("nodcolons")

    def test_colon_but_no_relation_separator(self) -> None:
        with pytest.raises(ValueError, match="Invalid relation tuple"):
            RelationTuple.parse("doc:readme")

    def test_valid_parse(self) -> None:
        rt = RelationTuple.parse("doc:readme#owner@user:alice")
        assert rt.object_id == "readme"
        assert rt.relation.name == "owner"
        assert rt.subject == "user:alice"

    def test_parse_with_no_subject(self) -> None:
        rt = RelationTuple.parse("doc:readme#owner")
        assert rt.subject is None

    def test_parse_with_unicode(self) -> None:
        try:
            rt = RelationTuple.parse("doc:\U0001f4a9#owner@user:alice")
            assert rt.object_id == "\U0001f4a9"
        except (ValueError, IndexError):
            pass  # Acceptable
