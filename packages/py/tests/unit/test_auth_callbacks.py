"""Tests for callback-based Auth construction (no subclassing)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from urauth.auth import Auth
from urauth.authz.primitives import Permission, Role
from urauth.config import AuthConfig
from urauth.exceptions import UnauthorizedError

SECRET = "test-secret-key-for-testing-only-32chars"


@dataclass
class FakeUser:
    id: str = "user-1"
    email: str = "alice@test.com"
    is_active: bool = True
    roles: list[str] = field(default_factory=lambda: ["admin"])
    password_hash: str = "hashed-secret"


USERS: dict[str, FakeUser] = {
    "user-1": FakeUser(id="user-1", email="alice@test.com", roles=["admin"]),
    "user-2": FakeUser(id="user-2", email="bob@test.com", roles=["viewer"]),
}


def _get_user(uid: Any) -> FakeUser | None:
    return USERS.get(str(uid))


def _get_user_by_username_match(name: Any) -> FakeUser | None:
    return next((u for u in USERS.values() if u.email == name), None)


def _get_user_by_username_none(name: Any) -> None:
    return None


def _verify_password_true(user: Any, pw: Any) -> bool:
    return pw == "secret"


def _verify_password_false(user: Any, pw: Any) -> bool:
    return False


def _get_user_none(uid: Any) -> None:
    return None


# ── Sync callbacks ──────────────────────────────────────────────


class TestSyncCallbacks:
    def test_basic_setup(self) -> None:
        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=_get_user,
            get_user_by_username=_get_user_by_username_match,
            verify_password=_verify_password_true,
        )
        token = auth.token_service.create_token_pair("user-1")
        ctx = auth.build_context_sync(token.access_token)
        assert ctx.is_authenticated()
        assert ctx.user.id == "user-1"

    def test_user_not_found(self) -> None:
        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=_get_user_none,
            get_user_by_username=_get_user_by_username_none,
            verify_password=_verify_password_false,
        )
        token = auth.token_service.create_token_pair("nonexistent")
        with pytest.raises(UnauthorizedError):
            auth.build_context_sync(token.access_token)

    def test_custom_roles(self) -> None:
        admin_role = Role("admin", [Permission("user:read"), Permission("user:write")])

        def _get_user_roles(user: Any) -> list[Role]:
            return [admin_role] if "admin" in user.roles else []

        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=_get_user,
            get_user_by_username=_get_user_by_username_none,
            verify_password=_verify_password_false,
            get_user_roles=_get_user_roles,
        )
        token = auth.token_service.create_token_pair("user-1")
        ctx = auth.build_context_sync(token.access_token)
        assert ctx.has_role(admin_role)
        assert ctx.has_permission(Permission("user:read"))

    def test_custom_permissions(self) -> None:
        extra_perm = Permission("special:access")

        def _get_user_permissions(user: Any) -> list[Permission]:
            return [extra_perm]

        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=_get_user,
            get_user_by_username=_get_user_by_username_none,
            verify_password=_verify_password_false,
            get_user_permissions=_get_user_permissions,
        )
        token = auth.token_service.create_token_pair("user-1")
        ctx = auth.build_context_sync(token.access_token)
        assert ctx.has_permission(extra_perm)


# ── Async callbacks ─────────────────────────────────────────────


class TestAsyncCallbacks:
    async def test_async_get_user(self) -> None:
        async def get_user(uid: Any) -> FakeUser | None:
            return USERS.get(str(uid))

        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=get_user,
            get_user_by_username=_get_user_by_username_match,
            verify_password=_verify_password_true,
        )
        token = auth.token_service.create_token_pair("user-1")
        ctx = await auth.build_context(token.access_token)
        assert ctx.is_authenticated()
        assert ctx.user.id == "user-1"

    async def test_all_async(self) -> None:
        async def get_user(uid: Any) -> FakeUser | None:
            return USERS.get(str(uid))

        async def get_by_username(name: str) -> FakeUser | None:
            return next((u for u in USERS.values() if u.email == name), None)

        async def verify(user: Any, pw: str) -> bool:
            return pw == "secret"

        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=get_user,
            get_user_by_username=get_by_username,
            verify_password=verify,
        )
        token = auth.token_service.create_token_pair("user-1")
        ctx = await auth.build_context(token.access_token)
        assert ctx.is_authenticated()

    async def test_optional_no_token(self) -> None:
        auth = Auth(
            config=AuthConfig(secret_key=SECRET),
            get_user=_get_user,
            get_user_by_username=_get_user_by_username_none,
            verify_password=_verify_password_false,
        )
        ctx = await auth.build_context(None, optional=True)
        assert not ctx.is_authenticated()


# ── Error when no callback or override ──────────────────────────


class TestMissingCallbacks:
    def test_no_get_user_raises(self) -> None:
        auth = Auth(config=AuthConfig(secret_key=SECRET))
        with pytest.raises(NotImplementedError, match="get_user"):
            auth.get_user("user-1")

    def test_no_get_user_by_username_raises(self) -> None:
        auth = Auth(config=AuthConfig(secret_key=SECRET))
        with pytest.raises(NotImplementedError, match="get_user_by_username"):
            auth.get_user_by_username("alice")

    def test_no_verify_password_raises(self) -> None:
        auth = Auth(config=AuthConfig(secret_key=SECRET))
        with pytest.raises(NotImplementedError, match="verify_password"):
            auth.verify_password(object(), "pw")


# ── Callback + subclass coexistence ─────────────────────────────


class TestCallbackSubclassCoexistence:
    def test_subclass_overrides_still_work(self) -> None:
        """Subclass overrides take priority over callables (method resolution order)."""

        class MyAuth(Auth):
            def get_user(self, user_id: Any) -> Any | None:
                return USERS.get(str(user_id))

            def get_user_by_username(self, username: str) -> Any | None:
                return None

            def verify_password(self, user: Any, password: str) -> bool:
                return False

        auth = MyAuth(config=AuthConfig(secret_key=SECRET))
        token = auth.token_service.create_token_pair("user-1")
        ctx = auth.build_context_sync(token.access_token)
        assert ctx.user.id == "user-1"
