"""Integration: Optional auth — public + authenticated endpoints."""

from __future__ import annotations

from httpx import AsyncClient

from tests.integration.conftest import login


class TestOptionalAuth:
    async def test_public_endpoint_no_token(self, client: AsyncClient) -> None:
        resp = await client.get("/feed")
        assert resp.status_code == 200
        assert resp.json()["type"] == "public"

    async def test_public_endpoint_with_valid_token(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]

        resp = await client.get("/feed", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "personalized"
        assert data["user_id"] == "admin-1"

    async def test_public_endpoint_with_invalid_token_returns_anonymous(self, client: AsyncClient) -> None:
        """Invalid token on optional endpoint should return anonymous, not error."""
        resp = await client.get("/feed", headers={"Authorization": "Bearer garbage-token"})
        assert resp.status_code == 200
        assert resp.json()["type"] == "public"

    async def test_protected_endpoint_no_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/me")
        assert resp.status_code == 401

    async def test_protected_endpoint_invalid_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/me", headers={"Authorization": "Bearer garbage-token"})
        assert resp.status_code == 401

    async def test_protected_endpoint_with_valid_token(self, client: AsyncClient) -> None:
        result = await login(client, "viewer@test.com", "viewer-pass")
        token = result["body"]["access_token"]

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["user_id"] == "viewer-1"


class TestOptionalAuthWithRevokedToken:
    async def test_revoked_token_on_optional_endpoint_returns_anonymous(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]

        # Logout (revokes token)
        await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})

        # Optional endpoint should return anonymous
        resp = await client.get("/feed", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["type"] == "public"

    async def test_revoked_token_on_protected_endpoint_returns_401(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]

        await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})

        resp = await client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
