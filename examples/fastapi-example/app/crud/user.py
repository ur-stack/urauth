"""User repository."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.user import User
from ..schemas.user import UserCreate, UserUpdate
from .base import CRUDBase


class UserRepository(CRUDBase[User, UserCreate, UserUpdate]):
    async def get_by_username(self, db: AsyncSession, username: str) -> User | None:
        result = await db.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def get_with_roles(self, db: AsyncSession, user_id: int) -> User | None:
        result = await db.execute(
            select(User)
            .options(selectinload(User.role_objects))
            .where(User.id == user_id)
        )
        return result.scalar_one_or_none()


user_repo = UserRepository(User)
