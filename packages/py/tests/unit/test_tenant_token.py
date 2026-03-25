"""Tests for tenant_path in token creation and validation."""

from __future__ import annotations

import pytest

from urauth.config import AuthConfig
from urauth.tokens.jwt import TokenService


@pytest.fixture
def svc() -> TokenService:
    return TokenService(AuthConfig(secret_key="test-secret", allow_insecure_key=True))


class TestTenantPathInTokens:
    def test_create_with_tenant_path(self, svc: TokenService) -> None:
        tenant_path = {"organization": "acme", "region": "us-west"}
        token = svc.create_access_token("user-1", tenant_path=tenant_path)
        payload = svc.validate_access_token(token)
        assert payload.tenant_path == tenant_path
        # tenant_id should be set to leaf value for backward compat
        assert payload.tenant_id == "us-west"

    def test_create_with_flat_tenant_id(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1", tenant_id="t-1")
        payload = svc.validate_access_token(token)
        assert payload.tenant_id == "t-1"
        assert payload.tenant_path is None

    def test_tenant_path_takes_precedence(self, svc: TokenService) -> None:
        tenant_path = {"organization": "acme"}
        token = svc.create_access_token(
            "user-1",
            tenant_id="should-be-overridden",
            tenant_path=tenant_path,
        )
        payload = svc.validate_access_token(token)
        assert payload.tenant_path == tenant_path
        assert payload.tenant_id == "acme"

    def test_no_tenant(self, svc: TokenService) -> None:
        token = svc.create_access_token("user-1")
        payload = svc.validate_access_token(token)
        assert payload.tenant_id is None
        assert payload.tenant_path is None

    def test_tenant_path_not_in_extra(self, svc: TokenService) -> None:
        tenant_path = {"organization": "acme"}
        token = svc.create_access_token("user-1", tenant_path=tenant_path)
        payload = svc.validate_access_token(token)
        assert "tenant_path" not in payload.extra

    def test_token_pair_with_tenant_path(self, svc: TokenService) -> None:
        tenant_path = {"org": "acme", "group": "team-a"}
        pair = svc.create_token_pair("user-1", tenant_path=tenant_path)
        payload = svc.validate_access_token(pair.access_token)
        assert payload.tenant_path == tenant_path
        assert payload.tenant_id == "team-a"
