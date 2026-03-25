"""Property-based tests for security-critical paths using Hypothesis."""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from urauth.authz.primitives import Permission, match_permission
from urauth.config import AuthConfig
from urauth.tokens.jwt import TokenService

# Use a fixed config for all property tests
_CONFIG = AuthConfig(secret_key="property-test-key-32-chars-long!", allow_insecure_key=True)
_SVC = TokenService(_CONFIG)

# Strategy for valid user IDs (non-empty, non-whitespace strings)
valid_user_ids = st.text(
    alphabet=string.ascii_letters + string.digits + "-_",
    min_size=1,
    max_size=64,
)

# Strategy for permission strings (resource:action format)
permission_strings = st.from_regex(r"[a-z]{1,10}:[a-z]{1,10}", fullmatch=True)


class TestJWTRoundTrip:
    """For any valid user_id, create → validate returns the original sub."""

    @given(user_id=valid_user_ids)
    @settings(max_examples=200)
    def test_access_token_round_trip(self, user_id: str) -> None:
        token = _SVC.create_access_token(user_id)
        payload = _SVC.validate_access_token(token)
        assert payload.sub == user_id
        assert payload.token_type == "access"

    @given(user_id=valid_user_ids)
    @settings(max_examples=200)
    def test_refresh_token_round_trip(self, user_id: str) -> None:
        token = _SVC.create_refresh_token(user_id)
        claims = _SVC.validate_refresh_token(token)
        assert claims["sub"] == user_id
        assert claims["type"] == "refresh"


class TestTokenTypeDiscrimination:
    """Access tokens never validate as refresh and vice versa."""

    @given(user_id=valid_user_ids)
    @settings(max_examples=100)
    def test_access_never_validates_as_refresh(self, user_id: str) -> None:
        from urauth.exceptions import InvalidTokenError

        token = _SVC.create_access_token(user_id)
        try:
            _SVC.validate_refresh_token(token)
            raise AssertionError("Should have raised InvalidTokenError")
        except InvalidTokenError:
            pass

    @given(user_id=valid_user_ids)
    @settings(max_examples=100)
    def test_refresh_never_validates_as_access(self, user_id: str) -> None:
        from urauth.exceptions import InvalidTokenError

        token = _SVC.create_refresh_token(user_id)
        try:
            _SVC.validate_access_token(token)
            raise AssertionError("Should have raised InvalidTokenError")
        except InvalidTokenError:
            pass


class TestReservedClaimProtection:
    """extra_claims with reserved keys never leak into the token."""

    @given(
        user_id=valid_user_ids,
        injected_sub=st.text(min_size=1, max_size=20),
        injected_jti=st.text(min_size=1, max_size=20),
    )
    @settings(max_examples=100)
    def test_reserved_claims_not_overridable(
        self, user_id: str, injected_sub: str, injected_jti: str
    ) -> None:
        extra = {
            "sub": injected_sub,
            "jti": injected_jti,
            "type": "evil",
            "exp": 9999999999,
            "iat": 0,
            "iss": "attacker",
            "aud": "attacker",
        }
        token = _SVC.create_access_token(user_id, extra_claims=extra)
        payload = _SVC.validate_access_token(token)
        assert payload.sub == user_id  # sub not overridden
        claims = _SVC.decode_token(token)
        assert claims["type"] == "access"  # type not overridden
        assert claims["exp"] < 9999999999  # exp not overridden


class TestPermissionReflexivity:
    """match_permission(p, p) is always True for any valid permission string."""

    @given(perm=permission_strings)
    @settings(max_examples=200)
    def test_permission_matches_itself(self, perm: str) -> None:
        p = Permission(perm)
        assert match_permission(p, p) is True

    @given(resource=st.from_regex(r"[a-z]{1,10}", fullmatch=True))
    @settings(max_examples=100)
    def test_wildcard_matches_any_action(self, resource: str) -> None:
        wildcard = Permission(f"{resource}:*")
        target = Permission(f"{resource}:read")
        assert match_permission(wildcard, target) is True


class TestPasswordHashRoundTrip:
    """For any password string, verify(password, hash(password)) is True."""

    @given(password=st.text(min_size=1, max_size=71, alphabet=string.printable))
    @settings(max_examples=20, deadline=2000)  # bcrypt is slow
    def test_hash_verify_round_trip(self, password: str) -> None:
        from urauth.authn.password import PasswordHasher

        hasher = PasswordHasher()
        hashed = hasher.hash(password)
        assert hasher.verify(password, hashed) is True
