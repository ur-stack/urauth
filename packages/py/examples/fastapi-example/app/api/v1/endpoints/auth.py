"""Auth endpoints (register, login, refresh, logout)."""

from __future__ import annotations

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import get_db
from app.core.security.auth import auth
from app.models.user import Role, User, UserRole
from app.schemas.user import UserCreate, UserRead
from urauth import PasswordHasher

router = auth.password_auth_router()
hasher = PasswordHasher()


@router.post("/register", response_model=UserRead, status_code=201)
async def register(body: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user with the default 'viewer' role."""
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Username already taken")

    user = User(
        username=body.username,
        password_hash=hasher.hash(body.password),
        department=body.department,
        level=body.level,
    )
    db.add(user)
    await db.flush()

    # Assign default 'viewer' role
    viewer_role = await db.execute(select(Role).where(Role.name == "viewer"))
    role = viewer_role.scalar_one_or_none()
    if role is not None:
        db.add(UserRole(user_id=user.id, role_id=role.id))
        await db.flush()

    await db.refresh(user)
    return UserRead.model_validate(user)
