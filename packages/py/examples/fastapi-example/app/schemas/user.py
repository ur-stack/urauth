"""User Pydantic schemas."""

from __future__ import annotations

from pydantic import BaseModel


class UserRead(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    username: str
    is_active: bool
    roles: list[str]
    department: str
    level: int


class UserCreate(BaseModel):
    username: str
    password: str
    department: str = ""
    level: int = 0


class UserUpdate(BaseModel):
    department: str | None = None
    level: int | None = None
    is_active: bool | None = None
