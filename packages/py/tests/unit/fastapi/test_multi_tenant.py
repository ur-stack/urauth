"""Tests for TenantResolver — JWT, header, path param, subdomain resolution."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from urauth.config import AuthConfig
from urauth.fastapi.authz.multi_tenant import TenantResolver
from urauth.fastapi.exceptions import register_exception_handlers


@dataclass(frozen=True, slots=True)
class _FakePayload:  # pyright: ignore[reportUnusedClass]
    """Minimal mock for TokenPayload."""

    tenant_id: str | None = None


def _make_app(config: AuthConfig | None = None) -> tuple[FastAPI, TenantResolver]:
    config = config or AuthConfig(secret_key="test")
    resolver = TenantResolver(config)

    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/tenant")
    async def get_tenant(tenant_id: str = Depends(resolver.current_tenant())) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"tenant_id": tenant_id}

    @app.get("/tenants/{tenant_id}/resources")
    async def get_resources(tenant_id: str = Depends(resolver.current_tenant())) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"tenant_id": tenant_id}

    return app, resolver


class TestTenantFromHeader:
    async def test_header_resolution(self) -> None:
        app, _ = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/tenant", headers={"X-Tenant-ID": "org-1"})
            assert resp.status_code == 200
            assert resp.json()["tenant_id"] == "org-1"

    async def test_custom_header_name(self) -> None:
        config = AuthConfig(secret_key="test", tenant_header="X-Org-ID")
        app, _ = _make_app(config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/tenant", headers={"X-Org-ID": "org-2"})
            assert resp.status_code == 200
            assert resp.json()["tenant_id"] == "org-2"


class TestTenantFromPathParam:
    async def test_path_param_resolution(self) -> None:
        app, _ = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/tenants/org-3/resources")
            assert resp.status_code == 200
            assert resp.json()["tenant_id"] == "org-3"


class TestTenantFromSubdomain:
    async def test_subdomain_resolution(self) -> None:
        app, _ = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/tenant", headers={"host": "acme.example.com"})
            assert resp.status_code == 200
            assert resp.json()["tenant_id"] == "acme"


class TestTenantMissing:
    async def test_no_tenant_returns_403(self) -> None:
        app, _ = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # No header, no path param, single-part host
            resp = await client.get("/tenant", headers={"host": "localhost"})
            assert resp.status_code == 403


class TestTenantPriority:
    async def test_header_takes_priority_over_subdomain(self) -> None:
        app, _ = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/tenant",
                headers={"X-Tenant-ID": "from-header", "host": "from-subdomain.example.com"},
            )
            assert resp.json()["tenant_id"] == "from-header"
