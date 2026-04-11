"""Task Pydantic schemas."""

from __future__ import annotations

from pydantic import BaseModel


class TaskRead(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    title: str
    description: str
    owner_id: int
    status: str
    is_public: bool


class TaskCreate(BaseModel):
    title: str
    description: str = ""
    is_public: bool = False


class TaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    is_public: bool | None = None
