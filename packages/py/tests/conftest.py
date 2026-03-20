from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from urauth import AuthConfig
from urauth.backends.memory import MemoryTokenStore


@dataclass
class FakeUser:
    id: str = "user-1"
    email: str = "alice@example.com"
    is_active: bool = True
    is_verified: bool = True
    roles: list[str] = field(default_factory=list)
    password_hash: str = ""


class FakeBackend:
    """In-memory user backend for testing."""

    def __init__(self, users: list[FakeUser] | None = None) -> None:
        self._users = {u.id: u for u in (users or [])}
        self._by_email = {u.email: u for u in (users or [])}

    async def get_by_id(self, user_id: str) -> FakeUser | None:
        return self._users.get(user_id)

    async def get_by_username(self, username: str) -> FakeUser | None:
        return self._by_email.get(username)

    async def verify_password(self, user: FakeUser, password: str) -> bool:
        return user.password_hash == password  # plaintext for tests


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(secret_key="test-secret-key-for-testing-only")


@pytest.fixture
def alice() -> FakeUser:
    return FakeUser(
        id="user-1",
        email="alice@example.com",
        roles=["admin"],
        password_hash="secret123",
    )


@pytest.fixture
def bob() -> FakeUser:
    return FakeUser(
        id="user-2",
        email="bob@example.com",
        roles=["viewer"],
        password_hash="password456",
    )


@pytest.fixture
def backend(alice: FakeUser, bob: FakeUser) -> FakeBackend:
    return FakeBackend([alice, bob])


@pytest.fixture
def token_store() -> MemoryTokenStore:
    return MemoryTokenStore()
