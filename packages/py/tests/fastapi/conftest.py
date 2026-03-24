from __future__ import annotations

import pytest

from tests.conftest import FakeBackend
from urauth import Auth, AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth


class _BackendAuth(Auth):
    """Auth subclass backed by FakeBackend for testing."""

    def __init__(self, backend: FakeBackend, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(**kwargs)
        self._backend = backend

    async def get_user(self, user_id):  # type: ignore[no-untyped-def]
        return await self._backend.get_by_id(str(user_id))

    async def get_user_by_username(self, username):  # type: ignore[no-untyped-def]
        return await self._backend.get_by_username(username)

    async def verify_password(self, user, password):  # type: ignore[no-untyped-def]
        return await self._backend.verify_password(user, password)


@pytest.fixture
def auth(backend: FakeBackend, config: AuthConfig, token_store: MemoryTokenStore) -> FastAuth:
    core = _BackendAuth(backend, config=config, token_store=token_store)
    return FastAuth(core)
