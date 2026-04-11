"""Tests for SQLAlchemy contrib package using async SQLite."""

from __future__ import annotations

import pytest
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from urauth.identity.password import PasswordHasher
from urauth.tokens.lifecycle import IssueRequest
from urauth.config import AuthConfig
from urauth.contrib.sqlalchemy import RoleMixin, UserMixin, create_sqlalchemy_auth, user_role_table

SECRET = "test-secret-key-for-testing-only-32chars"
HASHER = PasswordHasher(n=2**4)  # fast for tests


# ── Models ──────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


class User(Base, UserMixin):
    __tablename__ = "users"
    department: Mapped[str] = mapped_column(String(100), default="engineering")
    role_objects: Mapped[list[Role]] = relationship("Role", secondary="user_roles", lazy="selectin")

    @property
    def roles(self) -> list[str]:
        return [r.name for r in self.role_objects]


class Role(Base, RoleMixin):
    __tablename__ = "roles"


user_roles = user_role_table(Base)


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed data
    async with factory() as session:
        admin_role = Role(name="admin", description="Administrator")
        viewer_role = Role(name="viewer", description="Viewer")
        session.add_all([admin_role, viewer_role])
        await session.flush()

        alice = User(
            username="alice",
            email="alice@test.com",
            password_hash=HASHER.hash("secret123"),
            is_active=True,
            department="engineering",
        )
        bob = User(
            username="bob",
            email="bob@test.com",
            password_hash=HASHER.hash("password"),
            is_active=False,
            department="marketing",
        )
        session.add_all([alice, bob])
        await session.flush()

        # Assign roles via raw SQL (association table)
        await session.execute(user_roles.insert().values(user_id=alice.id, role_id=admin_role.id))
        await session.execute(user_roles.insert().values(user_id=bob.id, role_id=viewer_role.id))
        await session.commit()

    return factory


# ── Tests ───────────────────────────────────────────────────────


class TestCreateSQLAlchemyAuth:
    async def test_get_user_by_id(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
        )
        # Get user by id (need to find alice's id first)
        async with session_factory() as session:
            from sqlalchemy import select

            result = await session.execute(select(User).where(User.username == "alice"))
            alice = result.scalar_one()
            alice_id = alice.id

        token = await auth.lifecycle.issue(IssueRequest(user_id=str(alice_id)))
        ctx = await auth.build_context(token.access_token)
        assert ctx.is_authenticated()
        assert ctx.user.username == "alice"
        assert ctx.user.department == "engineering"

    async def test_roles_loaded(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
        )
        async with session_factory() as session:
            from sqlalchemy import select

            result = await session.execute(select(User).where(User.username == "alice"))
            alice = result.scalar_one()

        token = await auth.lifecycle.issue(IssueRequest(user_id=str(alice.id)))
        ctx = await auth.build_context(token.access_token)
        assert ctx.has_role("admin")

    async def test_get_user_by_username(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        from urauth.auth import maybe_await

        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
        )
        user = await maybe_await(auth.get_user_by_username("alice"))
        assert user is not None
        assert user.username == "alice"

    async def test_get_user_by_username_not_found(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        from urauth.auth import maybe_await

        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
        )
        user = await maybe_await(auth.get_user_by_username("nonexistent"))
        assert user is None

    async def test_verify_password(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        from urauth.auth import maybe_await

        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
        )
        user = await maybe_await(auth.get_user_by_username("alice"))
        assert user is not None

        valid = await maybe_await(auth.verify_password(user, "secret123"))
        assert valid is True

        invalid = await maybe_await(auth.verify_password(user, "wrong"))
        assert invalid is False

    async def test_inactive_user_rejected(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
        )
        async with session_factory() as session:
            from sqlalchemy import select

            result = await session.execute(select(User).where(User.username == "bob"))
            bob = result.scalar_one()

        token = await auth.lifecycle.issue(IssueRequest(user_id=str(bob.id)))
        from urauth.exceptions import UnauthorizedError

        with pytest.raises(UnauthorizedError, match="Inactive"):
            await auth.build_context(token.access_token)

    async def test_custom_username_field(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Test using email as the username field."""
        from urauth.auth import maybe_await

        auth = create_sqlalchemy_auth(
            session_factory,
            User,
            config=AuthConfig(secret_key=SECRET),
            hasher=HASHER,
            username_field="email",
        )
        user = await maybe_await(auth.get_user_by_username("alice@test.com"))
        assert user is not None
        assert user.username == "alice"


class TestModelMixins:
    def test_user_mixin_has_expected_columns(self) -> None:
        """UserMixin provides the expected column names."""
        mapper = User.__table__
        col_names = {c.name for c in mapper.columns}
        assert {"id", "username", "email", "password_hash", "is_active", "created_at", "updated_at"} <= col_names

    def test_role_mixin_has_expected_columns(self) -> None:
        mapper = Role.__table__
        col_names = {c.name for c in mapper.columns}
        assert {"id", "name", "description"} <= col_names

    def test_custom_column_present(self) -> None:
        mapper = User.__table__
        col_names = {c.name for c in mapper.columns}
        assert "department" in col_names

    def test_user_role_table_created(self) -> None:
        col_names = {c.name for c in user_roles.columns}
        assert col_names == {"user_id", "role_id"}
