"""SQLAlchemy model mixins for common auth tables.

Usage::

    from sqlalchemy.orm import DeclarativeBase, Mapped, relationship

    class Base(DeclarativeBase):
        pass

    class User(Base, UserMixin):
        __tablename__ = "users"
        # Add custom columns:
        department: Mapped[str] = mapped_column(String(100), default="")
        # Add role relationship:
        role_objects = relationship("Role", secondary="user_roles", lazy="selectin")

        @property
        def roles(self) -> list[str]:
            return [r.name for r in self.role_objects]

    class Role(Base, RoleMixin):
        __tablename__ = "roles"

    user_roles = user_role_table(Base)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, func
from sqlalchemy.orm import Mapped, mapped_column


class UserMixin:
    """Standard auth columns for a User model.

    Provides: ``id``, ``username``, ``email``, ``password_hash``,
    ``is_active``, ``created_at``, ``updated_at``.

    Users must set ``__tablename__`` and add a role relationship.
    """

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, onupdate=func.now(), nullable=True)


class RoleMixin:
    """Standard columns for a Role model.

    Provides: ``id``, ``name``, ``description``.
    """

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="", nullable=False)


def user_role_table(
    base: Any,
    *,
    table_name: str = "user_roles",
    user_table: str = "users",
    role_table: str = "roles",
) -> Table:
    """Create a user-role many-to-many association table.

    Args:
        base: Your SQLAlchemy ``DeclarativeBase`` class.
        table_name: Name for the association table.
        user_table: Name of the users table (for foreign key).
        role_table: Name of the roles table (for foreign key).
    """
    return Table(
        table_name,
        base.metadata,
        Column("user_id", Integer, ForeignKey(f"{user_table}.id", ondelete="CASCADE"), primary_key=True),
        Column("role_id", Integer, ForeignKey(f"{role_table}.id", ondelete="CASCADE"), primary_key=True),
    )
