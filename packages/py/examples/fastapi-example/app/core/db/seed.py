"""Create tables and seed initial data on startup."""

from __future__ import annotations

from sqlalchemy import select

from urauth import PasswordHasher

from app.core.db.base import Base, engine, async_session_factory
from app.models.user import Role, User, UserRole
from app.models.permission import Permission, RolePermission
from app.models.task import Task

hasher = PasswordHasher()


async def seed_database() -> None:
    """Create all tables and insert seed data if the DB is empty."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as session:
        # Skip seeding if data already exists
        existing = await session.execute(select(User).limit(1))
        if existing.scalar_one_or_none() is not None:
            return

        # ── Roles ─────────────────────────────────────────────
        admin_role = Role(name="admin")
        editor_role = Role(name="editor")
        viewer_role = Role(name="viewer")
        session.add_all([admin_role, editor_role, viewer_role])
        await session.flush()

        # ── Permissions ───────────────────────────────────────
        perm_names = [
            "tasks:read",
            "tasks:write",
            "tasks:update",
            "tasks:delete",
            "users:read",
            "users:write",
        ]
        perms = {name: Permission(name=name) for name in perm_names}
        session.add_all(perms.values())
        await session.flush()

        # ── Role → Permission mapping ─────────────────────────
        # admin gets all permissions
        for p in perms.values():
            session.add(RolePermission(role_id=admin_role.id, permission_id=p.id))

        # editor gets tasks:read, tasks:write, tasks:update
        for pname in ("tasks:read", "tasks:write", "tasks:update"):
            session.add(RolePermission(role_id=editor_role.id, permission_id=perms[pname].id))

        # viewer gets tasks:read
        session.add(RolePermission(role_id=viewer_role.id, permission_id=perms["tasks:read"].id))

        # ── Users ─────────────────────────────────────────────
        pw = hasher.hash("password123")

        alice = User(
            username="alice",
            password_hash=pw,
            department="engineering",
            level=10,
        )
        bob = User(
            username="bob",
            password_hash=pw,
            department="marketing",
            level=5,
        )
        charlie = User(
            username="charlie",
            password_hash=pw,
            department="engineering",
            level=2,
        )
        session.add_all([alice, bob, charlie])
        await session.flush()

        # ── User → Role mapping ───────────────────────────────
        session.add(UserRole(user_id=alice.id, role_id=admin_role.id))
        session.add(UserRole(user_id=bob.id, role_id=editor_role.id))
        session.add(UserRole(user_id=charlie.id, role_id=viewer_role.id))

        # ── Tasks ─────────────────────────────────────────────
        session.add_all([
            Task(title="Design API schema", description="Draft the OpenAPI spec", owner_id=alice.id, is_public=True),
            Task(title="Write blog post", description="Announce the launch", owner_id=bob.id, is_public=True),
            Task(title="Security audit", description="Internal review", owner_id=alice.id, is_public=False),
        ])

        await session.commit()
