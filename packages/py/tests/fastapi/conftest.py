from __future__ import annotations

import pytest

from tests.conftest import FakeBackend
from urauth import AuthConfig
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAPIAuth


@pytest.fixture
def auth(backend: FakeBackend, config: AuthConfig, token_store: MemoryTokenStore) -> FastAPIAuth:
    return FastAPIAuth(backend, config, token_store=token_store)


@pytest.fixture
def auth_callables(backend: FakeBackend, config: AuthConfig, token_store: MemoryTokenStore) -> FastAPIAuth:
    """Approach B: pass callables directly."""
    return FastAPIAuth(
        config=config,
        get_user=backend.get_by_id,
        get_user_by_username=backend.get_by_username,
        verify_password=backend.verify_password,
        token_store=token_store,
    )
