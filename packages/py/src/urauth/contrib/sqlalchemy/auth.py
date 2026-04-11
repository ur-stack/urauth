# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""SQLAlchemy user-data mixin and auth factory.

Preferred usage — mixin composition::

    from urauth import Auth
    from urauth.contrib.sqlalchemy import SQLAlchemyUserStore

    class MyAuth(Auth, SQLAlchemyUserStore):
        pass

    core = MyAuth(
        session_factory=async_session_factory,
        user_model=User,
        secret_key="...",
        method=JWT(ttl=900, store=MemoryTokenStore()),
        password=Password(),
    )
    auth = FastAuth(core)

Factory shorthand (equivalent)::

    from urauth.contrib.sqlalchemy import create_sqlalchemy_auth

    core = create_sqlalchemy_auth(
        session_factory=async_session_factory,
        user_model=User,
        secret_key="...",
        method=JWT(ttl=900, store=MemoryTokenStore()),
        password=Password(),
    )
    auth = FastAuth(core)
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from urauth.auth import Auth
from urauth.identity.password import PasswordHasher
from urauth.users import UserDataMixin


class SQLAlchemyUserStore(UserDataMixin):
    """User-data mixin backed by SQLAlchemy async sessions.

    Provides :meth:`get_user`, :meth:`get_user_by_username`, and
    :meth:`verify_password`. Use via multiple inheritance::

        class MyAuth(Auth, SQLAlchemyUserStore):
            pass
    """

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        user_model: type,
        hasher: PasswordHasher | None = None,
        username_field: str = "username",
        password_field: str = "password_hash",
        role_relationship: str | None = "role_objects",
        **kwargs: Any,
    ) -> None:
        self._session_factory = session_factory
        self._user_model = user_model
        self._hasher = hasher or PasswordHasher()
        self._username_field = username_field
        self._password_field = password_field
        self._options: list[Any] = []
        if role_relationship and hasattr(user_model, role_relationship):
            self._options.append(selectinload(getattr(user_model, role_relationship)))
        super().__init__(**kwargs)

    async def get_user(self, user_id: Any) -> Any | None:
        async with self._session_factory() as session:
            q = select(self._user_model).where(self._user_model.id == int(user_id))
            if self._options:
                q = q.options(*self._options)
            result = await session.execute(q)
            return result.scalar_one_or_none()

    async def get_user_by_username(self, username: str) -> Any | None:
        async with self._session_factory() as session:
            field = getattr(self._user_model, self._username_field)
            q = select(self._user_model).where(field == username)
            if self._options:
                q = q.options(*self._options)
            result = await session.execute(q)
            return result.scalar_one_or_none()

    async def verify_password(self, user: Any, password: str) -> bool:
        hashed: str = getattr(user, self._password_field)
        return self._hasher.verify(password, hashed)


def create_sqlalchemy_auth(
    session_factory: async_sessionmaker[AsyncSession],
    user_model: type,
    *,
    hasher: PasswordHasher | None = None,
    username_field: str = "username",
    password_field: str = "password_hash",
    role_relationship: str | None = "role_objects",
    **kwargs: Any,
) -> Auth:
    """Create an Auth instance wired to SQLAlchemy async queries.

    Equivalent to ``class _Auth(Auth, SQLAlchemyUserStore): pass`` followed
    by instantiation with all arguments forwarded.

    Args:
        session_factory: An ``async_sessionmaker`` for creating database sessions.
        user_model: Your SQLAlchemy User model class.
        hasher: Password hasher. Defaults to ``PasswordHasher()``.
        username_field: Column name used for username lookup. Default ``"username"``.
        password_field: Attribute name for the password hash. Default ``"password_hash"``.
        role_relationship: Relationship attribute to eager-load. Set to ``None`` to skip.
        **kwargs: Forwarded to ``Auth()`` (method, secret_key, password, etc.).
    """
    class _SQLAlchemyAuth(Auth, SQLAlchemyUserStore):
        pass

    return _SQLAlchemyAuth(
        session_factory=session_factory,
        user_model=user_model,
        hasher=hasher,
        username_field=username_field,
        password_field=password_field,
        role_relationship=role_relationship,
        **kwargs,
    )
