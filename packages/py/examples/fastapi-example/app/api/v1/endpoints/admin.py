"""Admin-only endpoints — demonstrates guard-based access control."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.core.security.auth import access
from app.models.permission import Perms
from app.schemas.user import UserRead
from app.services.user import user_service

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
@access.guard(Perms.USER_LIST)
async def list_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all users (admin only)."""
    users = await user_service.list_all(db)
    return [UserRead.model_validate(u) for u in users]


@router.post("/users/{user_id}/deactivate")
@access.guard(Perms.USER_DELETE)
async def deactivate_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (admin only)."""
    user = await user_service.deactivate(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserRead.model_validate(user)
