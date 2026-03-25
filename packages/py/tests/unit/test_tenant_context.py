"""Tests for tenant hierarchy in AuthContext and Auth."""

from __future__ import annotations

import pytest

from urauth.auth import Auth
from urauth.authz.primitives import Permission
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.tenant.hierarchy import TenantNode, TenantPath
from urauth.types import TokenPayload


class TestAuthContextTenant:
    @pytest.fixture
    def tenant_path(self) -> TenantPath:
        return TenantPath([
            TenantNode("acme", "organization"),
            TenantNode("us-west", "region"),
            TenantNode("team-a", "group"),
        ])

    def test_tenant_id_from_path(self, tenant_path: TenantPath) -> None:
        ctx = AuthContext(user=None, tenant=tenant_path)
        assert ctx.tenant_id == "team-a"

    def test_tenant_id_fallback_to_token(self) -> None:
        payload = TokenPayload(
            sub="u1", jti="j1", iat=0, exp=999999999, tenant_id="t-1"
        )
        ctx = AuthContext(user=None, token=payload)
        assert ctx.tenant_id == "t-1"

    def test_tenant_id_none(self) -> None:
        ctx = AuthContext(user=None)
        assert ctx.tenant_id is None

    def test_in_tenant(self, tenant_path: TenantPath) -> None:
        ctx = AuthContext(user=None, tenant=tenant_path)
        assert ctx.in_tenant("acme")
        assert ctx.in_tenant("us-west")
        assert ctx.in_tenant("team-a")
        assert not ctx.in_tenant("other")

    def test_in_tenant_no_path(self) -> None:
        ctx = AuthContext(user=None)
        assert not ctx.in_tenant("anything")

    def test_at_level(self, tenant_path: TenantPath) -> None:
        ctx = AuthContext(user=None, tenant=tenant_path)
        assert ctx.at_level("organization") == "acme"
        assert ctx.at_level("region") == "us-west"
        assert ctx.at_level("group") == "team-a"
        assert ctx.at_level("nonexistent") is None

    def test_at_level_no_path(self) -> None:
        ctx = AuthContext(user=None)
        assert ctx.at_level("organization") is None


class TestAuthResolveTenantPath:
    @pytest.fixture
    def auth(self) -> Auth:
        return Auth(
            config=AuthConfig(secret_key="test-secret", allow_insecure_key=True),
            token_store=MemoryTokenStore(),
            get_user=lambda uid: type("U", (), {"id": uid, "is_active": True})(),
            get_user_by_username=lambda name: None,
            verify_password=lambda u, p: False,
        )

    def test_resolve_from_token_path(self, auth: Auth) -> None:
        payload = TokenPayload(
            sub="u1", jti="j1", iat=0, exp=999999999,
            tenant_path={"organization": "acme", "region": "us-west"},
        )
        path = auth.resolve_tenant_path(None, payload)
        assert path is not None
        assert path.id_at("organization") == "acme"
        assert path.leaf_id == "us-west"

    def test_resolve_from_flat_tenant_id(self, auth: Auth) -> None:
        payload = TokenPayload(sub="u1", jti="j1", iat=0, exp=999999999, tenant_id="t-1")
        path = auth.resolve_tenant_path(None, payload)
        assert path is not None
        assert path.leaf_id == "t-1"

    def test_resolve_from_user_attribute(self, auth: Auth) -> None:
        user = type("U", (), {"tenant_id": "user-tenant"})()
        path = auth.resolve_tenant_path(user, None)
        assert path is not None
        assert path.leaf_id == "user-tenant"

    def test_resolve_none(self, auth: Auth) -> None:
        path = auth.resolve_tenant_path(None, None)
        assert path is None


class TestAuthBuildUserContextWithTenant:
    @pytest.mark.asyncio
    async def test_build_context_populates_tenant(self) -> None:
        user = type("U", (), {"id": "u1", "is_active": True, "roles": []})()

        class TenantAuth(Auth):
            def resolve_tenant_path(self, user, payload):  # type: ignore[override]
                return TenantPath([
                    TenantNode("acme", "organization"),
                    TenantNode("team-a", "group"),
                ])

            def get_tenant_permissions(self, user, level, tenant_id):  # type: ignore[override]
                if level == "organization":
                    return [Permission("org", "read")]
                return []

        auth = TenantAuth(
            config=AuthConfig(secret_key="test", allow_insecure_key=True),
            token_store=MemoryTokenStore(),
        )
        ctx = await auth.build_user_context(user)
        assert ctx.tenant is not None
        assert ctx.tenant.leaf_id == "team-a"
        assert ctx.tenant_id == "team-a"
        assert ctx.in_tenant("acme")
        assert "organization" in ctx.scopes
        assert any(str(p) == "org:read" for p in ctx.scopes["organization"])

    @pytest.mark.asyncio
    async def test_build_context_no_tenant(self) -> None:
        user = type("U", (), {"id": "u1", "is_active": True, "roles": []})()
        auth = Auth(
            config=AuthConfig(secret_key="test", allow_insecure_key=True),
            token_store=MemoryTokenStore(),
            get_user=lambda uid: user,
            get_user_by_username=lambda name: None,
            verify_password=lambda u, p: False,
        )
        ctx = await auth.build_user_context(user)
        assert ctx.tenant is None
        assert ctx.tenant_id is None
        assert ctx.scopes == {}
