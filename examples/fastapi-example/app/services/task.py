"""Task service layer."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from ..crud.task import task_repo
from ..models.task import Task
from ..schemas.task import TaskCreate, TaskUpdate


class TaskService:
    async def list_visible(
        self, db: AsyncSession, user_id: int, *, skip: int = 0, limit: int = 100
    ) -> list[Task]:
        return await task_repo.get_visible_for_user(db, user_id, skip=skip, limit=limit)

    async def create(self, db: AsyncSession, task_in: TaskCreate, owner_id: int) -> Task:
        task = Task(**task_in.model_dump(), owner_id=owner_id)
        db.add(task)
        await db.flush()
        await db.refresh(task)
        return task

    async def get(self, db: AsyncSession, task_id: int) -> Task | None:
        return await task_repo.get(db, task_id)

    async def update(
        self, db: AsyncSession, task: Task, task_in: TaskUpdate
    ) -> Task:
        return await task_repo.update(db, db_obj=task, obj_in=task_in)

    async def delete(self, db: AsyncSession, task_id: int) -> bool:
        return await task_repo.delete(db, id=task_id)


task_service = TaskService()
