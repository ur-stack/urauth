"""SQLModel base models for common auth tables.

Usage::

    from urauth.contrib.sqlmodel import UserBase, RoleBase

    class User(UserBase, table=True):
        __tablename__ = "users"
        department: str = ""

    class Role(RoleBase, table=True):
        __tablename__ = "roles"
"""

from __future__ import annotations

from datetime import datetime

from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    """Base fields for a User model. Subclass with ``table=True``."""

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True, max_length=255)
    email: str | None = Field(default=None, unique=True, index=True, max_length=255)
    password_hash: str = Field(max_length=255)
    is_active: bool = Field(default=True)
    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)


class RoleBase(SQLModel):
    """Base fields for a Role model. Subclass with ``table=True``."""

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, max_length=50)
    description: str = Field(default="", max_length=255)
