# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false
"""SQLAlchemy auth factory — create a pre-wired Auth instance.

Usage::

    from urauth.contrib.sqlalchemy import create_sqlalchemy_auth

    core = create_sqlalchemy_auth(
        session_factory=async_session_factory,
        user_model=User,
        config=AuthConfig(secret_key="..."),
    )
    auth = FastAuth(core)
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from urauth.auth import Auth
from urauth.authn.password import PasswordHasher
from urauth.backends.base import TokenStore
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig


def create_sqlalchemy_auth(
    session_factory: async_sessionmaker[AsyncSession],
    user_model: type,
    *,
    config: AuthConfig | None = None,
    token_store: TokenStore | None = None,
    hasher: PasswordHasher | None = None,
    username_field: str = "username",
    password_field: str = "password_hash",
    role_relationship: str | None = "role_objects",
    pipeline: Any | None = None,
) -> Auth:
    """Create an Auth instance wired to SQLAlchemy async queries.

    Args:
        session_factory: An ``async_sessionmaker`` for creating database sessions.
        user_model: Your SQLAlchemy User model class.
        config: Auth configuration. Defaults to ``AuthConfig()``.
        token_store: Token revocation store. Defaults to ``MemoryTokenStore()``.
        hasher: Password hasher. Defaults to ``PasswordHasher()``.
        username_field: Column name used for username lookup. Default ``"username"``.
        password_field: Attribute name for the password hash. Default ``"password_hash"``.
        role_relationship: Relationship attribute to eager-load. Set to ``None`` to skip.
        pipeline: Optional pipeline configuration.
    """
    _hasher = hasher or PasswordHasher()

    # Build selectinload options for eager loading
    _options: list[Any] = []
    if role_relationship and hasattr(user_model, role_relationship):
        _options.append(selectinload(getattr(user_model, role_relationship)))

    async def _get_user(user_id: Any) -> Any | None:
        async with session_factory() as session:
            q = select(user_model).where(user_model.id == int(user_id))
            if _options:
                q = q.options(*_options)
            result = await session.execute(q)
            return result.scalar_one_or_none()

    async def _get_user_by_username(username: str) -> Any | None:
        async with session_factory() as session:
            field = getattr(user_model, username_field)
            q = select(user_model).where(field == username)
            if _options:
                q = q.options(*_options)
            result = await session.execute(q)
            return result.scalar_one_or_none()

    async def _verify_password(user: Any, password: str) -> bool:
        hashed: str = getattr(user, password_field)
        return _hasher.verify(password, hashed)

    return Auth(
        config=config,
        token_store=token_store or MemoryTokenStore(),
        pipeline=pipeline,
        get_user=_get_user,
        get_user_by_username=_get_user_by_username,
        verify_password=_verify_password,
    )
