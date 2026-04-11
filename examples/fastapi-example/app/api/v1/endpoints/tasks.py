"""Task CRUD — demonstrates typed permission auth patterns with SQLAlchemy."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.core.security.auth import access, auth
from app.models.permission import Perms
from app.schemas.task import TaskCreate, TaskUpdate
from app.services.task import task_service
from urauth.context import AuthContext

router = APIRouter(prefix="/tasks", tags=["tasks"])


# ── Pattern 1: @access.guard() with typed Permission ─────────


@router.get("/")
@access.guard(Perms.TASK_READ)
async def list_tasks(
    request: Request,
    ctx: AuthContext = Depends(auth.context),
    db: AsyncSession = Depends(get_db),
):
    """List all public tasks + tasks owned by the current user."""
    tasks = await task_service.list_visible(db, ctx.user.id)
    return [
        {"id": t.id, "title": t.title, "status": t.status, "owner_id": t.owner_id}
        for t in tasks
    ]


# ── Pattern 2: @access.guard() with typed write ──────────────


@router.post("/", status_code=201)
@access.guard(Perms.TASK_WRITE)
async def create_task(
    body: TaskCreate,
    request: Request,
    ctx: AuthContext = Depends(auth.context),
    db: AsyncSession = Depends(get_db),
):
    """Create a new task owned by the current user."""
    task = await task_service.create(db, body, owner_id=ctx.user.id)
    return {"id": task.id, "title": task.title}


# ── Pattern 3: @access.guard() with typed read ───────────────


@router.get("/{task_id}")
@access.guard(Perms.TASK_READ)
async def get_task(
    task_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get a single task — access checked via guard decorator."""
    task = await task_service.get(db, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "status": task.status,
        "owner_id": task.owner_id,
        "is_public": task.is_public,
    }


# ── Pattern 4: Depends(access.guard()) ───────────────────────


@router.put("/{task_id}", dependencies=[Depends(access.guard(Perms.TASK_UPDATE))])
async def update_task(
    task_id: int,
    body: TaskUpdate,
    ctx: AuthContext = Depends(auth.context),
    db: AsyncSession = Depends(get_db),
):
    """Update a task — access checked via Depends()."""
    task = await task_service.get(db, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    updated = await task_service.update(db, task, body)
    return {"id": updated.id, "title": updated.title, "status": updated.status}


# ── Pattern 5: access.check() inline ─────────────────────────


@router.delete("/{task_id}", status_code=204)
async def delete_task(
    task_id: int,
    request: Request,
    ctx: AuthContext = Depends(auth.context),
    db: AsyncSession = Depends(get_db),
):
    """Delete a task — access checked inline with access.check()."""
    allowed = await access.check(Perms.TASK_DELETE, request=request)
    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied")
    deleted = await task_service.delete(db, task_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Task not found")
