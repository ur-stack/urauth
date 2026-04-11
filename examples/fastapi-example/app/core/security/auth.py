"""Central auth wiring — demonstrates RoleRegistry-based access control."""

from __future__ import annotations

from app.core.config import settings
from app.core.db.base import async_session_factory
from app.crud.user import user_repo
from app.models.permission import Perms
from urauth import JWT, Auth, Password, PasswordHasher, ResetablePassword
from urauth.authz import RoleRegistry
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

hasher = PasswordHasher()


# ── Core auth instance ───────────────────────────────────────


class AppAuth(Auth):
    async def get_user(self, user_id):
        async with async_session_factory() as session:
            return await user_repo.get_with_roles(session, int(user_id))

    async def get_user_by_username(self, username):
        async with async_session_factory() as session:
            return await user_repo.get_by_username(session, username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.password_hash)


core = AppAuth(
    method=JWT(
        ttl=settings.ACCESS_TOKEN_TTL,
        refresh_ttl=settings.REFRESH_TOKEN_TTL,
        refresh=True,
        revocable=True,
        store=MemoryTokenStore(),
    ),
    secret_key=settings.SECRET_KEY,
    password=ResetablePassword(),
)
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
