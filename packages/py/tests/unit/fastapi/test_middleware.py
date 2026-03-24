"""Tests for CSRF and TokenRefresh middleware."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from starlette.responses import JSONResponse

from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.middleware import CSRFMiddleware, TokenRefreshMiddleware
from urauth.tokens.jwt import TokenService

SECRET = "test-secret-key-32-chars-long-xx"


# ── CSRF Middleware ─────────────────────────────────────────────


def _csrf_app() -> FastAPI:
    app = FastAPI()
    config = AuthConfig(secret_key=SECRET)
    app.add_middleware(CSRFMiddleware, config=config)

    @app.get("/page")
    async def get_page() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"ok": "yes"}

    @app.post("/submit")
    async def post_submit() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"ok": "yes"}

    @app.head("/page")
    async def head_page() -> None:  # pyright: ignore[reportUnusedFunction]
        return None

    return app


@pytest.fixture
async def csrf_client() -> AsyncIterator[AsyncClient]:
    app = _csrf_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestCSRFMiddleware:
    async def test_get_sets_csrf_cookie(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.get("/page")
        assert resp.status_code == 200
        assert "csrf_token" in resp.cookies

    async def test_get_does_not_reset_existing_cookie(self, csrf_client: AsyncClient) -> None:
        # First GET sets cookie
        resp1 = await csrf_client.get("/page")
        token1 = resp1.cookies["csrf_token"]

        # Second GET with cookie already set should not overwrite
        resp2 = await csrf_client.get("/page", cookies={"csrf_token": token1})
        assert resp2.status_code == 200
        # The cookie should not be re-set in response
        assert "csrf_token" not in resp2.cookies

    async def test_post_without_csrf_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post("/submit")
        assert resp.status_code == 403
        assert "CSRF" in resp.text

    async def test_post_with_mismatched_tokens_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post(
            "/submit",
            cookies={"csrf_token": "token-a"},
            headers={"X-CSRF-Token": "token-b"},
        )
        assert resp.status_code == 403

    async def test_post_with_matching_tokens_passes(self, csrf_client: AsyncClient) -> None:
        # Get CSRF token
        resp = await csrf_client.get("/page")
        csrf_token = resp.cookies["csrf_token"]

        # POST with matching cookie and header
        resp = await csrf_client.post(
            "/submit",
            cookies={"csrf_token": csrf_token},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert resp.status_code == 200

    async def test_post_with_cookie_but_no_header_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post(
            "/submit",
            cookies={"csrf_token": "some-token"},
        )
        assert resp.status_code == 403

    async def test_post_with_header_but_no_cookie_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post(
            "/submit",
            headers={"X-CSRF-Token": "some-token"},
        )
        assert resp.status_code == 403

    async def test_head_is_safe_method(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.head("/page")
        assert resp.status_code == 200


# ── Token Refresh Middleware ────────────────────────────────────


class _FakeTransport:
    """Minimal transport for testing."""

    def __init__(self) -> None:
        self.last_set_token: str | None = None

    def extract_token(self, request: Request) -> str | None:
        return request.cookies.get("access_token")

    def set_token(self, response: JSONResponse, token: str) -> None:
        self.last_set_token = token
        response.set_cookie("access_token", token)

    def delete_token(self, response: JSONResponse) -> None:
        response.delete_cookie("access_token")


def _refresh_app(threshold: int = 300) -> tuple[FastAPI, TokenService, _FakeTransport]:
    config = AuthConfig(secret_key=SECRET)
    svc = TokenService(config)
    transport = _FakeTransport()
    store = MemoryTokenStore()

    app = FastAPI()
    app.add_middleware(
        TokenRefreshMiddleware, token_service=svc, transport=transport, token_store=store, threshold=threshold
    )

    @app.get("/protected")
    async def protected() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"ok": "yes"}

    return app, svc, transport


class TestTokenRefreshMiddleware:
    async def test_no_token_passthrough(self) -> None:
        app, _, transport = _refresh_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected")
            assert resp.status_code == 200
            assert transport.last_set_token is None

    async def test_token_not_near_expiry_no_refresh(self) -> None:
        app, svc, transport = _refresh_app(threshold=300)
        # Token with 15 min TTL — not near expiry
        token = svc.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", cookies={"access_token": token})
            assert resp.status_code == 200
            assert transport.last_set_token is None

    async def test_token_near_expiry_gets_refreshed(self) -> None:
        # Use a very short TTL and high threshold so it triggers
        config = AuthConfig(secret_key=SECRET, access_token_ttl=10)
        svc = TokenService(config)
        transport = _FakeTransport()
        store = MemoryTokenStore()
        app = FastAPI()
        app.add_middleware(
            TokenRefreshMiddleware, token_service=svc, transport=transport, token_store=store, threshold=300
        )

        @app.get("/protected")
        async def protected() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": "yes"}

        token = svc.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", cookies={"access_token": token})
            assert resp.status_code == 200
            assert transport.last_set_token is not None
            assert transport.last_set_token != token  # new token

    async def test_invalid_token_no_error(self) -> None:
        """Invalid token should not cause middleware to error — just pass through."""
        app, _, transport = _refresh_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", cookies={"access_token": "garbage"})
            assert resp.status_code == 200
            assert transport.last_set_token is None

    async def test_expired_token_no_crash(self) -> None:
        """Truly expired token should not crash the middleware."""
        config = AuthConfig(secret_key=SECRET, access_token_ttl=-1)
        expired_svc = TokenService(config)
        transport = _FakeTransport()
        store = MemoryTokenStore()
        app = FastAPI()
        app.add_middleware(
            TokenRefreshMiddleware, token_service=expired_svc, transport=transport, token_store=store, threshold=300
        )

        @app.get("/protected")
        async def protected() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": "yes"}

        token = expired_svc.create_access_token("user-1")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", cookies={"access_token": token})
            assert resp.status_code == 200
            assert transport.last_set_token is None

    async def test_refreshed_token_preserves_claims(self) -> None:
        """When a token is refreshed, sub/scopes/roles/tenant_id are preserved."""
        config = AuthConfig(secret_key=SECRET, access_token_ttl=10)
        svc = TokenService(config)
        transport = _FakeTransport()
        store = MemoryTokenStore()
        app = FastAPI()
        app.add_middleware(
            TokenRefreshMiddleware, token_service=svc, transport=transport, token_store=store, threshold=300
        )

        @app.get("/protected")
        async def protected() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": "yes"}

        token = svc.create_access_token(
            "user-1", scopes=["read", "write"], roles=["admin"], tenant_id="acme"
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/protected", cookies={"access_token": token})
            assert resp.status_code == 200
            assert transport.last_set_token is not None

        # Validate the refreshed token has same claims
        new_payload = svc.validate_access_token(transport.last_set_token)
        assert new_payload.sub == "user-1"
        assert new_payload.scopes == ["read", "write"]
        assert new_payload.roles == ["admin"]
        assert new_payload.tenant_id == "acme"
