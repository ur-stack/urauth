"""Testing utilities for urauth FastAPI adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute

from urauth.config import AuthConfig
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPair


def create_test_token(
    user_id: str = "test-user",
    *,
    secret_key: str = "test-secret",
    algorithm: str = "HS256",
    scopes: list[str] | None = None,
    roles: list[str] | None = None,
    tenant_id: str | None = None,
    fresh: bool = False,
    extra_claims: dict[str, Any] | None = None,
    access_ttl: int = 3600,
    refresh_ttl: int = 86400,
) -> TokenPair:
    """Create a token pair for testing without needing a full FastAuth setup."""
    config = AuthConfig(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_ttl=access_ttl,
        refresh_token_ttl=refresh_ttl,
        allow_insecure_key=True,
    )
    svc = TokenService(config)
    return svc.create_token_pair(
        user_id,
        scopes=scopes,
        roles=roles,
        tenant_id=tenant_id,
        fresh=fresh,
        extra_claims=extra_claims,
    )


@dataclass
class _MockUser:
    id: str = "test-user"
    is_active: bool = True
    is_verified: bool = True
    roles: list[str] = field(default_factory=list)
    email: str = "test@example.com"


class AuthOverride:
    """Context manager to override auth dependencies in tests.

    Usage::

        from urauth.fastapi.testing import AuthOverride

        override = AuthOverride(auth, app)

        def test_protected_route():
            with override.as_user(mock_user, roles=["admin"]):
                resp = client.get("/admin")
                assert resp.status_code == 200
    """

    def __init__(self, auth: Any, app: FastAPI) -> None:
        self._auth = auth
        self._app = app

    def as_user(
        self,
        user: Any | None = None,
        *,
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
        user_id: str = "test-user",
    ) -> _AuthOverrideContext:
        if user is None:
            user = _MockUser(id=user_id, roles=roles or [])
        return _AuthOverrideContext(self._auth, self._app, user)


class _AuthOverrideContext:
    def __init__(self, auth: Any, app: FastAPI, user: Any) -> None:
        self._auth = auth
        self._app = app
        self._user = user
        self._originals: dict[Any, Any] = {}

    def __enter__(self) -> _AuthOverrideContext:
        user = self._user
        for route in self._app.routes:
            if not isinstance(route, APIRoute):
                continue
            for dep in route.dependant.dependencies or []:
                call = dep.call
                if call is None:
                    continue
                # Check if this callable was produced by FastAuth
                is_auth_dep = hasattr(call, "__qualname__") and (
                    "current_user" in call.__qualname__ or "context" in call.__qualname__
                )
                if is_auth_dep:

                    async def _override() -> Any:
                        return user

                    self._originals[call] = self._app.dependency_overrides.get(call)
                    self._app.dependency_overrides[call] = _override

        return self

    def __exit__(self, *args: Any) -> None:
        for call, original in self._originals.items():
            if original is None:
                self._app.dependency_overrides.pop(call, None)
            else:
                self._app.dependency_overrides[call] = original
