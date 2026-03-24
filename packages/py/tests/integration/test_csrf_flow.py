"""Integration: CSRF protection in a browser-style flow."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from tests.integration.conftest import (
    SECRET,
    USERS,
    IntegrationAuth,
    build_app,
)
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.auth import FastAuth


@pytest.fixture
async def csrf_client() -> AsyncIterator[AsyncClient]:
    config = AuthConfig(secret_key=SECRET)
    store = MemoryTokenStore()
    core = IntegrationAuth(dict(USERS), config=config, token_store=store)
    fast = FastAuth(core)
    app = build_app(fast, csrf=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestCSRFProtectionFlow:
    async def test_get_sets_csrf_cookie(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.get("/feed")
        assert resp.status_code == 200
        assert "csrf_token" in resp.cookies

    async def test_post_with_matching_csrf_succeeds(self, csrf_client: AsyncClient) -> None:
        # GET to obtain CSRF token
        resp = await csrf_client.get("/feed")
        csrf_token = resp.cookies["csrf_token"]

        # POST with matching cookie + header
        resp = await csrf_client.post(
            "/auth/login",
            json={"username": "admin@test.com", "password": "admin-pass"},
            cookies={"csrf_token": csrf_token},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert resp.status_code == 200

    async def test_post_without_csrf_cookie_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post(
            "/auth/login",
            json={"username": "admin@test.com", "password": "admin-pass"},
            headers={"X-CSRF-Token": "some-token"},
        )
        assert resp.status_code == 403
        assert "CSRF" in resp.text

    async def test_post_without_csrf_header_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post(
            "/auth/login",
            json={"username": "admin@test.com", "password": "admin-pass"},
            cookies={"csrf_token": "some-token"},
        )
        assert resp.status_code == 403

    async def test_post_with_mismatched_csrf_fails(self, csrf_client: AsyncClient) -> None:
        resp = await csrf_client.post(
            "/auth/login",
            json={"username": "admin@test.com", "password": "admin-pass"},
            cookies={"csrf_token": "token-a"},
            headers={"X-CSRF-Token": "token-b"},
        )
        assert resp.status_code == 403
