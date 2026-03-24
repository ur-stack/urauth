"""Central auth wiring — demonstrates RoleRegistry-based access control."""

from __future__ import annotations

from app.core.config import auth_config
from app.core.db.base import async_session_factory
from app.crud.user import user_repo
from app.models.permission import Perms
from app.models.user import User
from urauth import Auth, PasswordHasher
from urauth.authz import RoleRegistry
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

hasher = PasswordHasher()


class _AppAuth(Auth):
    """Auth backed by SQLAlchemy — opens its own sessions."""

    async def get_user(self, user_id: int | str) -> User | None:
        async with async_session_factory() as session:
            return await user_repo.get_with_roles(session, int(user_id))

    async def get_user_by_username(self, username: str) -> User | None:
        async with async_session_factory() as session:
            return await user_repo.get_by_username(session, username)

    async def verify_password(self, user: User, password: str) -> bool:
        return hasher.verify(password, user.password_hash)


# ── Core auth instance ───────────────────────────────────────

core = _AppAuth(auth_config, token_store=MemoryTokenStore())
auth = FastAuth(core)

# ── RoleRegistry-based access control ────────────────────────

builtin = RoleRegistry()
builtin.role("admin", permissions=["*"])

tasks = RoleRegistry()
tasks.role("editor", permissions=[Perms.TASK_READ, Perms.TASK_WRITE, Perms.TASK_UPDATE])
tasks.role("viewer", permissions=[Perms.TASK_READ])

registry = RoleRegistry()
registry.include(builtin)
registry.include(tasks)
registry.role("admin", permissions=["*"], inherits=["editor", "viewer"])
registry.role("editor", permissions=[Perms.TASK_READ, Perms.TASK_WRITE, Perms.TASK_UPDATE], inherits=["viewer"])

access = auth.access_control(registry=registry)
