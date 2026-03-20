"""Tests for testing utilities."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.conftest import FakeBackend, FakeUser
from urauth import AuthConfig
from urauth.fastapi import FastAPIAuth
from urauth.fastapi.exceptions import register_exception_handlers
from urauth.fastapi.testing import AuthOverride, create_test_token


class TestCreateTestToken:
    def test_creates_valid_pair(self) -> None:
        pair = create_test_token(user_id="u1", roles=["admin"])
        assert pair.access_token
        assert pair.refresh_token
        assert pair.token_type == "bearer"


class TestAuthOverride:
    @pytest.mark.asyncio
    async def test_override_bypasses_auth(self) -> None:
        alice = FakeUser(id="user-1", email="alice@example.com", roles=["admin"])
        backend = FakeBackend([alice])
        config = AuthConfig(secret_key="test-key")
        auth = FastAPIAuth(backend, config)

        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/me")
        async def me(user=auth.current_user()):
            return {"id": user.id, "email": user.email}

        override = AuthOverride(auth, app)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Without override: should fail (no token)
            resp = await client.get("/me")
            assert resp.status_code == 401

            # With override: should succeed
            with override.as_user(alice):
                resp = await client.get("/me")
                assert resp.status_code == 200
                assert resp.json()["email"] == "alice@example.com"

            # After exiting: should fail again
            resp = await client.get("/me")
            assert resp.status_code == 401
