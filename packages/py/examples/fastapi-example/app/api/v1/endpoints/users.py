"""Current-user endpoints — demonstrates current_user() and requires()."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.security.auth import auth

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
async def get_profile(user=auth.current_user()):
    """Return the current user's profile."""
    return {
        "id": user.id,
        "username": user.username,
        "roles": user.roles,
        "department": user.department,
        "level": user.level,
    }


@router.get("/me/admin-check")
async def admin_check(user=auth.requires(roles=["admin"])):
    """Only accessible to admins."""
    return {"message": f"Hello admin {user.username}"}
