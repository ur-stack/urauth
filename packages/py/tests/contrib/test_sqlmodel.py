"""Tests for SQLModel contrib package using async SQLite."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import Field, SQLModel

from urauth.authn.password import PasswordHasher
from urauth.config import AuthConfig
from urauth.contrib.sqlmodel import RoleBase, UserBase, create_sqlmodel_auth

SECRET = "test-secret-key-for-testing-only-32chars"
HASHER = PasswordHasher(rounds=4)


# ── Models ──────────────────────────────────────────────────────


class User(UserBase, table=True):
    __tablename__ = "sm_users"
    department: str = Field(default="engineering")


class Role(RoleBase, table=True):
    __tablename__ = "sm_roles"


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed
    async with factory() as session:
        alice = User(
            username="alice",
            email="alice@test.com",
            password_hash=HASHER.hash("secret123"),
            is_active=True,
        )
        bob = User(
            username="bob",
            email="bob@test.com",
            password_hash=HASHER.hash("password"),
            is_active=False,
        )
        session.add_all([alice, bob])
        await session.commit()

    return factory


# ── Tests ───────────────────────────────────────────────────────


class TestCreateSQLModelAuth:
    async def test_get_user_by_id(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        auth = create_sqlmodel_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
            role_relationship=None,  # No roles for this simple test
        )
        # Find alice's ID
        async with session_factory() as session:
            from sqlmodel import select

            result = await session.execute(select(User).where(User.username == "alice"))
            alice = result.scalar_one()

        token = auth.token_service.create_token_pair(str(alice.id))
        ctx = await auth.build_context(token.access_token)
        assert ctx.is_authenticated()
        assert ctx.user.username == "alice"
        assert ctx.user.department == "engineering"

    async def test_get_user_by_username(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        from urauth.auth import maybe_await

        auth = create_sqlmodel_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
            role_relationship=None,
        )
        user = await maybe_await(auth.get_user_by_username("alice"))
        assert user is not None
        assert user.username == "alice"

    async def test_verify_password(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        from urauth.auth import maybe_await

        auth = create_sqlmodel_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
            role_relationship=None,
        )
        user = await maybe_await(auth.get_user_by_username("alice"))
        assert user is not None
        assert await maybe_await(auth.verify_password(user, "secret123")) is True
        assert await maybe_await(auth.verify_password(user, "wrong")) is False

    async def test_inactive_user_rejected(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        auth = create_sqlmodel_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
            role_relationship=None,
        )
        async with session_factory() as session:
            from sqlmodel import select

            result = await session.execute(select(User).where(User.username == "bob"))
            bob = result.scalar_one()

        token = auth.token_service.create_token_pair(str(bob.id))
        from urauth.exceptions import UnauthorizedError

        with pytest.raises(UnauthorizedError, match="Inactive"):
            await auth.build_context(token.access_token)


class TestModelBases:
    def test_user_base_fields(self) -> None:
        columns = {c.name for c in User.__table__.columns}
        assert {"id", "username", "email", "password_hash", "is_active"} <= columns

    def test_custom_column_present(self) -> None:
        columns = {c.name for c in User.__table__.columns}
        assert "department" in columns

    def test_role_base_fields(self) -> None:
        columns = {c.name for c in Role.__table__.columns}
        assert {"id", "name", "description"} <= columns
