"""User service layer."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ..crud.user import user_repo
from ..models.user import User


class UserService:
    async def get_profile(self, db: AsyncSession, user_id: int) -> User | None:
        return await user_repo.get_with_roles(db, user_id)

    async def list_all(
        self, db: AsyncSession, *, skip: int = 0, limit: int = 100
    ) -> list[User]:
        return await user_repo.get_multi(db, skip=skip, limit=limit)

    async def deactivate(self, db: AsyncSession, user_id: int) -> User | None:
        user = await user_repo.get(db, user_id)
        if user is None:
            return None
        user.is_active = False
        await db.flush()
        await db.refresh(user)
        return user


user_service = UserService()
