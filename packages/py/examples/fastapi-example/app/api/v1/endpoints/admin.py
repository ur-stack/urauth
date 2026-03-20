"""Admin-only endpoints — demonstrates role-based requires()."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.core.security.auth import auth
from app.schemas.user import UserRead
from app.services.user import user_service

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
async def list_users(
    _=auth.requires(roles=["admin"]),
    db: AsyncSession = Depends(get_db),
):
    """List all users (admin only)."""
    users = await user_service.list_all(db)
    return [UserRead.model_validate(u) for u in users]


@router.post("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    _=auth.requires(roles=["admin"]),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (admin only)."""
    user = await user_service.deactivate(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserRead.model_validate(user)
