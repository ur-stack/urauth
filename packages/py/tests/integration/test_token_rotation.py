"""Integration: Refresh token rotation and replay attack detection."""

from __future__ import annotations

from httpx import AsyncClient

from tests.integration.conftest import login


class TestNormalRefreshRotation:
    async def test_refresh_returns_new_pair(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        old_refresh = result["body"]["refresh_token"]
        old_access = result["body"]["access_token"]

        # Rotate
        resp = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
        assert resp.status_code == 200
        new_pair = resp.json()
        assert new_pair["access_token"] != old_access
        assert new_pair["refresh_token"] != old_refresh

    async def test_new_access_token_works(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        old_refresh = result["body"]["refresh_token"]

        resp = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
        new_token = resp.json()["access_token"]

        resp = await client.get("/me", headers={"Authorization": f"Bearer {new_token}"})
        assert resp.status_code == 200
        assert resp.json()["user_id"] == "admin-1"

    async def test_old_refresh_token_revoked_after_rotation(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        old_refresh = result["body"]["refresh_token"]

        # First rotation succeeds
        await client.post("/auth/refresh", json={"refresh_token": old_refresh})

        # Second use of old refresh token → reuse detected
        resp = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
        assert resp.status_code == 401


class TestRefreshTokenReplayAttack:
    async def test_replay_revokes_entire_family(self, client: AsyncClient) -> None:
        """Simulates stolen token replay: attacker replays old refresh token,
        entire family is revoked, legitimate user loses access."""
        # Step 1: Login → pair 1
        result = await login(client, "admin@test.com", "admin-pass")
        stolen_refresh = result["body"]["refresh_token"]

        # Step 2: Legitimate rotation → pair 2
        resp = await client.post("/auth/refresh", json={"refresh_token": stolen_refresh})
        assert resp.status_code == 200
        pair2 = resp.json()

        # Step 3: Attacker replays stolen refresh token
        resp = await client.post("/auth/refresh", json={"refresh_token": stolen_refresh})
        assert resp.status_code == 401  # Reuse detected

        # Step 4: Even pair 2's access token is now revoked (family revocation)
        resp = await client.get("/me", headers={"Authorization": f"Bearer {pair2['access_token']}"})
        assert resp.status_code == 401

    async def test_replay_does_not_affect_other_family(self, client: AsyncClient) -> None:
        """Replay attack on session A should not affect session B."""
        # Login session A
        result_a = await login(client, "admin@test.com", "admin-pass")
        stolen_refresh_a = result_a["body"]["refresh_token"]

        # Login session B
        result_b = await login(client, "admin@test.com", "admin-pass")
        token_b = result_b["body"]["access_token"]

        # Rotate session A, then replay
        await client.post("/auth/refresh", json={"refresh_token": stolen_refresh_a})
        await client.post("/auth/refresh", json={"refresh_token": stolen_refresh_a})  # replay

        # Session B should still work
        resp = await client.get("/me", headers={"Authorization": f"Bearer {token_b}"})
        assert resp.status_code == 200


class TestRefreshWithInvalidToken:
    async def test_garbage_token(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/refresh", json={"refresh_token": "garbage"})
        assert resp.status_code == 401

    async def test_access_token_as_refresh(self, client: AsyncClient) -> None:
        """Using an access token as a refresh token should fail."""
        result = await login(client, "admin@test.com", "admin-pass")
        access = result["body"]["access_token"]

        resp = await client.post("/auth/refresh", json={"refresh_token": access})
        assert resp.status_code == 401
