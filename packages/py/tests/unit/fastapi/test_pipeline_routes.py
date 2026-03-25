"""Tests for pipeline-driven route generation."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from urauth.auth import Auth
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.pipeline import (
    BasicAuthStrategy,
    Identifiers,
    JWTStrategy,
    MagicLinkLogin,
    MFAMethod,
    OTPLogin,
    Pipeline,
    SessionStrategy,
)

# ── Test Auth subclass ───────────────────────────────────────────


class _User:
    def __init__(self, id: str, username: str, password: str, is_active: bool = True):
        self.id = id
        self.username = username
        self.password = password
        self.is_active = is_active
        self.roles: list[str] = []


_USERS = {
    "user1": _User("user1", "alice", "secret123"),
    "user2": _User("user2", "bob", "pass456"),
}

_USERS_BY_NAME = {u.username: u for u in _USERS.values()}

# Reset token store for tests
_RESET_TOKENS: dict[str, str] = {}


class _TestAuth(Auth):
    def get_user(self, user_id: Any) -> Any:
        return _USERS.get(user_id)

    def get_user_by_username(self, username: str) -> Any:
        return _USERS_BY_NAME.get(username)

    def get_user_by_identifier(self, identifier: str) -> Any:
        return _USERS_BY_NAME.get(identifier)

    def verify_password(self, user: Any, password: str) -> bool:
        return user.password == password

    # MFA hooks
    def is_mfa_enrolled(self, user: Any) -> bool:
        return False

    def get_mfa_methods(self, user: Any) -> list[str]:
        return []

    def verify_mfa(self, user: Any, method: str, code: str) -> bool:
        return code == "123456"

    # OTP
    def verify_otp(self, user: Any, code: str) -> bool:
        return code == "654321"

    # Magic link
    def send_magic_link(self, email: str, token: str, link: str) -> None:
        pass  # no-op in tests

    def verify_magic_link_token(self, token: str) -> Any:
        if token == "valid-token":
            return _USERS["user1"]
        return None

    # Password reset
    def create_reset_token(self, user: Any) -> str:
        token = "reset-token-123"
        _RESET_TOKENS[token] = user.id
        return token

    def send_reset_email(self, email: str, token: str, link: str) -> None:
        pass

    def validate_reset_token(self, token: str) -> Any:
        user_id = _RESET_TOKENS.get(token)
        if user_id:
            return _USERS.get(user_id)
        return None

    def invalidate_password(self, user: Any) -> None:
        user.password = None  # simulate invalidation

    def set_password(self, user: Any, new_password: str) -> None:
        user.password = new_password


# ── Fixtures ─────────────────────────────────────────────────────


def _make_app(pipeline: Pipeline) -> FastAPI:
    config = AuthConfig(secret_key="test-secret-key-for-pipeline", allow_insecure_key=True)
    core = _TestAuth(config=config, token_store=MemoryTokenStore(), pipeline=pipeline)
    auth = FastAuth(core)
    app = FastAPI()
    auth.init_app(app)
    app.include_router(auth.auto_router())

    @app.get("/protected")
    async def protected(ctx: AuthContext = Depends(auth.context)):  # pyright: ignore[reportUnusedFunction]
        return {"user_id": ctx.user.id}

    return app


def _make_client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ── JWT + Password tests ────────────────────────────────────────


class TestJWTPasswordPipeline:
    @pytest.fixture
    def app(self):
        return _make_app(Pipeline(strategy=JWTStrategy(refresh=True, revocable=True), password=True))

    @pytest.mark.anyio
    async def test_login_success(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            assert resp.status_code == 200
            data = resp.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"

    @pytest.mark.anyio
    async def test_login_invalid_credentials(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/login", json={"username": "alice", "password": "wrong"})
            assert resp.status_code == 401

    @pytest.mark.anyio
    async def test_protected_with_token(self, app: FastAPI):
        async with _make_client(app) as client:
            login = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            token = login.json()["access_token"]
            resp = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            assert resp.json()["user_id"] == "user1"

    @pytest.mark.anyio
    async def test_refresh(self, app: FastAPI):
        async with _make_client(app) as client:
            login = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            refresh_token = login.json()["refresh_token"]
            resp = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
            assert resp.status_code == 200
            assert "access_token" in resp.json()

    @pytest.mark.anyio
    async def test_logout(self, app: FastAPI):
        async with _make_client(app) as client:
            login = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            token = login.json()["access_token"]
            resp = await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 204

    @pytest.mark.anyio
    async def test_logout_all(self, app: FastAPI):
        async with _make_client(app) as client:
            login = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            token = login.json()["access_token"]
            resp = await client.post("/auth/logout-all", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 204


# ── Identifier-based login ──────────────────────────────────────


class TestIdentifierLogin:
    @pytest.fixture
    def app(self):
        return _make_app(
            Pipeline(
                strategy=JWTStrategy(),
                password=True,
                identifiers=Identifiers(email=True, phone=True),
            )
        )

    @pytest.mark.anyio
    async def test_login_with_identifier(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/login", json={"identifier": "alice", "password": "secret123"})
            assert resp.status_code == 200
            assert "access_token" in resp.json()


# ── OTP login ───────────────────────────────────────────────────


class TestOTPPipeline:
    @pytest.fixture
    def app(self):
        return _make_app(Pipeline(strategy=JWTStrategy(), otp=OTPLogin(code_type="numeric", digits=6)))

    @pytest.mark.anyio
    async def test_otp_verify_success(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/otp/verify", json={"username": "alice", "code": "654321"})
            assert resp.status_code == 200
            assert "access_token" in resp.json()

    @pytest.mark.anyio
    async def test_otp_verify_invalid(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/otp/verify", json={"username": "alice", "code": "000000"})
            assert resp.status_code == 401


# ── Magic link login ────────────────────────────────────────────


class TestMagicLinkPipeline:
    @pytest.fixture
    def app(self):
        return _make_app(Pipeline(strategy=JWTStrategy(), magic_link=MagicLinkLogin()))

    @pytest.mark.anyio
    async def test_send_magic_link(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/magic-link/send", json={"email": "alice@test.com"})
            assert resp.status_code == 202

    @pytest.mark.anyio
    async def test_verify_valid_token(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/magic-link/verify", json={"token": "valid-token"})
            assert resp.status_code == 200
            assert "access_token" in resp.json()

    @pytest.mark.anyio
    async def test_verify_invalid_token(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/magic-link/verify", json={"token": "bad-token"})
            assert resp.status_code == 401


# ── Password reset (3-step) ─────────────────────────────────────


class TestPasswordResetPipeline:
    @pytest.fixture
    def app(self):
        # Reset user password for each test
        _USERS["user1"].password = "secret123"
        _RESET_TOKENS.clear()
        return _make_app(Pipeline(strategy=JWTStrategy(), password=True, password_reset=True))

    @pytest.mark.anyio
    async def test_forgot_password(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/password/forgot", json={"email": "alice"})
            assert resp.status_code == 202

    @pytest.mark.anyio
    async def test_full_reset_flow(self, app: FastAPI):
        async with _make_client(app) as client:
            # Step 1: Request reset
            await client.post("/auth/password/forgot", json={"email": "alice"})

            # Step 2: Confirm token (invalidates old password)
            resp = await client.post("/auth/password/reset/confirm", json={"token": "reset-token-123"})
            assert resp.status_code == 200
            data = resp.json()
            assert "reset_session" in data

            # Old password should be invalidated now
            login_resp = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            assert login_resp.status_code == 401

            # Step 3: Set new password
            resp = await client.post(
                "/auth/password/reset/complete",
                json={"reset_session": data["reset_session"], "new_password": "new-pass-123"},
            )
            assert resp.status_code == 200

            # Can login with new password
            login_resp = await client.post("/auth/login", json={"username": "alice", "password": "new-pass-123"})
            assert login_resp.status_code == 200

    @pytest.mark.anyio
    async def test_confirm_invalid_token(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/password/reset/confirm", json={"token": "invalid"})
            assert resp.status_code == 401


# ── Session strategy ────────────────────────────────────────────


class TestSessionPipeline:
    @pytest.fixture
    def app(self):
        from urauth.backends.memory import MemorySessionStore

        config = AuthConfig(secret_key="test-secret-key-session", allow_insecure_key=True)
        core = _TestAuth(
            config=config,
            token_store=MemoryTokenStore(),
            session_store=MemorySessionStore(),
            pipeline=Pipeline(strategy=SessionStrategy(), password=True),
        )
        auth = FastAuth(core)
        app = FastAPI()
        auth.init_app(app)
        app.include_router(auth.auto_router())
        return app

    @pytest.mark.anyio
    async def test_session_login(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            assert resp.status_code == 200
            assert "session_id" in resp.json()

    @pytest.mark.anyio
    async def test_session_logout(self, app: FastAPI):
        async with _make_client(app) as client:
            login = await client.post("/auth/login", json={"username": "alice", "password": "secret123"})
            cookies = login.cookies
            resp = await client.post("/auth/logout", cookies=cookies)
            assert resp.status_code == 204


# ── Basic auth strategy ─────────────────────────────────────────


class TestBasicAuthPipeline:
    @pytest.fixture
    def app(self):
        config = AuthConfig(secret_key="test-secret-key-basic", allow_insecure_key=True)
        core = _TestAuth(
            config=config,
            token_store=MemoryTokenStore(),
            pipeline=Pipeline(strategy=BasicAuthStrategy()),
        )
        auth = FastAuth(core)
        app = FastAPI()
        auth.init_app(app)

        @app.get("/protected")
        async def protected(ctx: AuthContext = Depends(auth.context)):  # pyright: ignore[reportUnusedFunction]
            return {"user_id": ctx.user.id}

        return app

    @pytest.mark.anyio
    async def test_basic_auth_success(self, app: FastAPI):
        import base64

        creds = base64.b64encode(b"alice:secret123").decode()
        async with _make_client(app) as client:
            resp = await client.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 200
            assert resp.json()["user_id"] == "user1"

    @pytest.mark.anyio
    async def test_basic_auth_invalid(self, app: FastAPI):
        import base64

        creds = base64.b64encode(b"alice:wrong").decode()
        async with _make_client(app) as client:
            resp = await client.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 401

    @pytest.mark.anyio
    async def test_basic_auth_missing(self, app: FastAPI):
        async with _make_client(app) as client:
            resp = await client.get("/protected")
            assert resp.status_code == 401


# ── Route generation verification ───────────────────────────────


class TestRouteGeneration:
    def test_jwt_password_routes(self):
        app = _make_app(Pipeline(strategy=JWTStrategy(refresh=True, revocable=True), password=True))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/login" in paths
        assert "/auth/refresh" in paths
        assert "/auth/logout" in paths
        assert "/auth/logout-all" in paths

    def test_jwt_no_refresh_routes(self):
        app = _make_app(Pipeline(strategy=JWTStrategy(refresh=False), password=True))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/login" in paths
        assert "/auth/refresh" not in paths
        assert "/auth/logout" in paths

    def test_jwt_not_revocable_no_logout_all(self):
        app = _make_app(Pipeline(strategy=JWTStrategy(revocable=False), password=True))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/logout-all" not in paths

    def test_otp_routes(self):
        app = _make_app(Pipeline(otp=OTPLogin()))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/otp/verify" in paths

    def test_magic_link_routes(self):
        app = _make_app(Pipeline(magic_link=MagicLinkLogin()))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/magic-link/send" in paths
        assert "/auth/magic-link/verify" in paths

    def test_password_reset_routes(self):
        app = _make_app(Pipeline(password=True, password_reset=True))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/password/forgot" in paths
        assert "/auth/password/reset/confirm" in paths
        assert "/auth/password/reset/complete" in paths

    def test_mfa_routes(self):
        app = _make_app(Pipeline(password=True, mfa=[MFAMethod(method="otp")]))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/mfa/challenge" in paths
        assert "/auth/mfa/verify" in paths
        assert "/auth/mfa/enroll" in paths
        assert "/auth/mfa/methods" in paths

    def test_passkey_routes(self):
        app = _make_app(Pipeline(passkey=True))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/passkey/login/begin" in paths
        assert "/auth/passkey/login/complete" in paths
        assert "/auth/passkey/register/begin" in paths
        assert "/auth/passkey/register/complete" in paths
        assert "/auth/passkey/list" in paths
        assert "/auth/passkey/{credential_id}" in paths

    def test_session_routes(self):
        app = _make_app(Pipeline(strategy=SessionStrategy(), password=True))
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/login" in paths
        assert "/auth/logout" in paths
        assert "/auth/refresh" not in paths

    def test_empty_pipeline_no_login(self):
        app = _make_app(Pipeline())
        paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
        assert "/auth/login" not in paths

    def test_auto_router_without_pipeline_raises(self):
        config = AuthConfig(secret_key="test", allow_insecure_key=True)
        core = _TestAuth(config=config)
        auth = FastAuth(core)
        with pytest.raises(RuntimeError, match=r"auto_router.*requires.*Pipeline"):
            auth.auto_router()
