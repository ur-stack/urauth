"""Current-user endpoints — demonstrates AuthContext and guard()."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.security.auth import access, auth
from urauth.context import AuthContext

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
async def get_profile(ctx: AuthContext = Depends(auth.context)):
    """Return the current user's profile."""
    return {
        "id": ctx.user.id,
        "username": ctx.user.username,
        "roles": ctx.user.roles,
        "department": ctx.user.department,
        "level": ctx.user.level,
    }


@router.get("/me/admin-check")
@access.guard("user", "read")
async def admin_check(request: Request, ctx: AuthContext = Depends(auth.context)):
    """Only accessible to users with user:read permission."""
    return {"message": f"Hello admin {ctx.user.username}"}
