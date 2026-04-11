"""Integration: Complete authentication lifecycle — login, use, logout."""

from __future__ import annotations

from httpx import AsyncClient

from tests.integration.conftest import login


class TestLoginSuccess:
    async def test_login_returns_tokens(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        assert result["status"] == 200
        body = result["body"]
        assert "access_token" in body
        assert "refresh_token" not in body  # delivered via httpOnly cookie, not body
        assert body["token_type"] == "bearer"
        # Refresh token is in the httpOnly cookie
        assert result["response"].cookies.get("refresh_token") is not None

    async def test_access_protected_with_token(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["user_id"] == "admin-1"
        assert resp.json()["authenticated"] is True


class TestLoginFailure:
    async def test_wrong_password(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/login", json={"identifier": "admin@test.com", "password": "wrong"})
        assert resp.status_code == 401

    async def test_nonexistent_user(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/login", json={"identifier": "nobody@test.com", "password": "pass"})
        assert resp.status_code == 401

    async def test_inactive_user(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/login", json={"identifier": "inactive@test.com", "password": "pass"})
        assert resp.status_code == 401

    async def test_no_token_gets_401(self, client: AsyncClient) -> None:
        resp = await client.get("/me")
        assert resp.status_code == 401


class TestLogoutFlow:
    async def test_logout_revokes_session(self, client: AsyncClient) -> None:
        # Login
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]

        # Verify token works
        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

        # Logout
        resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

        # Token should now be revoked
        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    async def test_login_again_after_logout(self, client: AsyncClient) -> None:
        # Login → logout → login again
        result1 = await login(client, "admin@test.com", "admin-pass")
        token1 = result1["body"]["access_token"]

        await client.post("/auth/logout", headers={"Authorization": f"Bearer {token1}"})

        # Fresh login should work
        result2 = await login(client, "admin@test.com", "admin-pass")
        token2 = result2["body"]["access_token"]
        assert token2 != token1

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token2}"})
        assert resp.status_code == 200
