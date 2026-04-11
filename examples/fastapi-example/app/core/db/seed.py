"""Create tables and seed initial data on startup."""

from __future__ import annotations

from sqlalchemy import select

from app.core.db.base import Base, async_session_factory, engine
from app.models.task import Task
from app.models.user import Role, User, UserRole
from urauth import PasswordHasher

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

        # ── Roles (permissions stored as JSON column) ────────
        admin_role = Role(name="admin", permissions=["*"])
        editor_role = Role(name="editor", permissions=["task:read", "task:write", "task:update"])
        viewer_role = Role(name="viewer", permissions=["task:read"])
        session.add_all([admin_role, editor_role, viewer_role])
        await session.flush()

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
