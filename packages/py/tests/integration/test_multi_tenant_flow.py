"""Integration: Multi-tenant isolation across requests."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from tests.integration.conftest import (
    SECRET,
    USERS,
    IntegrationAuth,
)
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.authz.multi_tenant import TenantResolver
from urauth.fastapi.exceptions import register_exception_handlers


@pytest.fixture
async def tenant_client() -> AsyncIterator[AsyncClient]:
    config = AuthConfig(secret_key=SECRET, tenant_enabled=True)
    store = MemoryTokenStore()
    core = IntegrationAuth(dict(USERS), config=config, token_store=store)
    fast = FastAuth(core)
    resolver = TenantResolver(config)

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(fast.password_auth_router())

    @app.get("/tenant-data")
    async def get_tenant_data(  # pyright: ignore[reportUnusedFunction]
        ctx: AuthContext = Depends(fast.context),
        tenant_id: str = Depends(resolver.current_tenant()),
    ) -> dict[str, str]:
        return {"user": ctx.user.id, "tenant": tenant_id}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestTenantIsolation:
    async def test_tenant_from_header(self, tenant_client: AsyncClient) -> None:
        # Login
        resp = await tenant_client.post(
            "/auth/login",
            json={"identifier": "admin@test.com", "password": "admin-pass"},
        )
        token = resp.json()["access_token"]

        # Access with tenant header
        resp = await tenant_client.get(
            "/tenant-data",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "org-1"},
        )
        assert resp.status_code == 200
        assert resp.json()["tenant"] == "org-1"

    async def test_different_tenants_resolve_separately(self, tenant_client: AsyncClient) -> None:
        resp = await tenant_client.post(
            "/auth/login",
            json={"identifier": "admin@test.com", "password": "admin-pass"},
        )
        token = resp.json()["access_token"]

        resp1 = await tenant_client.get(
            "/tenant-data",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "org-1"},
        )
        resp2 = await tenant_client.get(
            "/tenant-data",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "org-2"},
        )
        assert resp1.json()["tenant"] == "org-1"
        assert resp2.json()["tenant"] == "org-2"

    async def test_missing_tenant_returns_403(self, tenant_client: AsyncClient) -> None:
        resp = await tenant_client.post(
            "/auth/login",
            json={"identifier": "admin@test.com", "password": "admin-pass"},
        )
        token = resp.json()["access_token"]

        resp = await tenant_client.get(
            "/tenant-data",
            headers={"Authorization": f"Bearer {token}", "host": "localhost"},
        )
        assert resp.status_code == 403
