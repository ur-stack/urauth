"""Central auth wiring — demonstrates RBAC, permissions, and policy-based access control."""

from __future__ import annotations

from typing import Any

from urauth import PasswordHasher
from urauth.authz.policy import ABACPolicy, AnyOf, RBACPolicy
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAPIAuth

from app.core.config import auth_config
from app.core.db.base import async_session_factory
from app.crud.user import user_repo

hasher = PasswordHasher()


class UserBackendImpl:
    """UserBackend backed by SQLAlchemy — opens its own sessions."""

    async def get_by_id(self, user_id: Any) -> Any | None:
        async with async_session_factory() as session:
            return await user_repo.get_with_roles(session, int(user_id))

    async def get_by_username(self, username: str) -> Any | None:
        async with async_session_factory() as session:
            return await user_repo.get_by_username(session, username)

    async def verify_password(self, user: Any, password: str) -> bool:
        return hasher.verify(password, user.password_hash)


# ── Core auth instance ───────────────────────────────────────

backend = UserBackendImpl()
auth = FastAPIAuth(backend, auth_config, token_store=MemoryTokenStore())

# ── RBAC hierarchy ───────────────────────────────────────────

auth.set_rbac({"admin": ["editor", "viewer"], "editor": ["viewer"]})

# ── Permission map ───────────────────────────────────────────

auth.set_permissions(
    {
        "admin": {"*"},
        "editor": {"tasks:read", "tasks:write", "tasks:update"},
        "viewer": {"tasks:read"},
    }
)

# ── Policy-based access control ──────────────────────────────

rbac_policy = (
    RBACPolicy()
    .grant("admin", "read", "write", "update", "delete")
    .grant("editor", "read", "write", "update")
    .grant("viewer", "read")
    .inherit("editor", "viewer")
)

engineering_policy = (
    ABACPolicy()
    .when("subject.attributes.department")
    .equals("engineering")
    .when("subject.attributes.level")
    .gte(5)
)

combined_policy = AnyOf(rbac_policy, engineering_policy)

access = auth.access_control(combined_policy)
