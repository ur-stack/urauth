"""Integration: Multi-session management — multi-device, selective revocation."""

from __future__ import annotations

from httpx import AsyncClient

from tests.integration.conftest import login


class TestMultiDeviceSessions:
    async def test_two_sessions_work_independently(self, client: AsyncClient) -> None:
        # Login from "device A"
        result_a = await login(client, "admin@test.com", "admin-pass")
        token_a = result_a["body"]["access_token"]

        # Login from "device B"
        result_b = await login(client, "admin@test.com", "admin-pass")
        token_b = result_b["body"]["access_token"]

        # Both sessions work
        resp_a = await client.get("/me", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 200
        resp_b = await client.get("/me", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 200

    async def test_logout_one_device_keeps_other(self, client: AsyncClient) -> None:
        result_a = await login(client, "admin@test.com", "admin-pass")
        token_a = result_a["body"]["access_token"]

        result_b = await login(client, "admin@test.com", "admin-pass")
        token_b = result_b["body"]["access_token"]

        # Logout device A
        await client.post("/auth/logout", headers={"Authorization": f"Bearer {token_a}"})

        # Device A revoked
        resp_a = await client.get("/me", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 401

        # Device B still works
        resp_b = await client.get("/me", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 200

    async def test_logout_all_revokes_every_session(self, client: AsyncClient) -> None:
        result_a = await login(client, "admin@test.com", "admin-pass")
        token_a = result_a["body"]["access_token"]

        result_b = await login(client, "admin@test.com", "admin-pass")
        token_b = result_b["body"]["access_token"]

        # Logout all from device A
        await client.post("/auth/logout-all", headers={"Authorization": f"Bearer {token_a}"})

        # Both sessions revoked
        resp_a = await client.get("/me", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 401

        resp_b = await client.get("/me", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 401

    async def test_different_users_sessions_isolated(self, client: AsyncClient) -> None:
        result_admin = await login(client, "admin@test.com", "admin-pass")
        token_admin = result_admin["body"]["access_token"]

        result_viewer = await login(client, "viewer@test.com", "viewer-pass")
        token_viewer = result_viewer["body"]["access_token"]

        # Logout all for admin
        await client.post("/auth/logout-all", headers={"Authorization": f"Bearer {token_admin}"})

        # Admin revoked
        resp = await client.get("/me", headers={"Authorization": f"Bearer {token_admin}"})
        assert resp.status_code == 401

        # Viewer still works
        resp = await client.get("/me", headers={"Authorization": f"Bearer {token_viewer}"})
        assert resp.status_code == 200
