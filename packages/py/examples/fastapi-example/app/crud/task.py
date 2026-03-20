"""Task repository."""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.task import Task
from ..schemas.task import TaskCreate, TaskUpdate
from .base import CRUDBase


class TaskRepository(CRUDBase[Task, TaskCreate, TaskUpdate]):
    async def get_visible_for_user(
        self, db: AsyncSession, user_id: int, *, skip: int = 0, limit: int = 100
    ) -> list[Task]:
        result = await db.execute(
            select(Task)
            .where(or_(Task.is_public.is_(True), Task.owner_id == user_id))
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())


task_repo = TaskRepository(Task)
