"""Integration: RBAC/permission enforcement across the full request cycle."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from tests.integration.conftest import (
    SECRET,
    USERS,
    IntegrationAuth,
    admin_manage,
    member_of,
    task_read,
)
from urauth.authz.roles import RoleRegistry
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.exceptions import register_exception_handlers

from .conftest import login


class TestRBACEnforcement:
    async def test_admin_accesses_admin_endpoint(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_viewer_denied_admin_endpoint(self, client: AsyncClient) -> None:
        result = await login(client, "viewer@test.com", "viewer-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    async def test_viewer_accesses_task_list(self, client: AsyncClient) -> None:
        result = await login(client, "viewer@test.com", "viewer-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/tasks", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_viewer_denied_task_create(self, client: AsyncClient) -> None:
        result = await login(client, "viewer@test.com", "viewer-pass")
        token = result["body"]["access_token"]
        resp = await client.post("/tasks", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    async def test_editor_can_create_tasks(self, client: AsyncClient) -> None:
        result = await login(client, "editor@test.com", "editor-pass")
        token = result["body"]["access_token"]
        resp = await client.post("/tasks", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_editor_denied_admin(self, client: AsyncClient) -> None:
        result = await login(client, "editor@test.com", "editor-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


class TestRelationEnforcement:
    async def test_owner_accesses_owned_resource(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/tasks/task-1", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_non_owner_denied(self, client: AsyncClient) -> None:
        result = await login(client, "admin@test.com", "admin-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/tasks/task-999", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    async def test_different_user_denied(self, client: AsyncClient) -> None:
        result = await login(client, "viewer@test.com", "viewer-pass")
        token = result["body"]["access_token"]
        resp = await client.get("/tasks/task-1", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


class TestComposableRequirements:
    """Test composite AND/OR permission requirements."""

    async def test_composite_requirement(self) -> None:
        """Endpoint requires (task_read & member_of) | admin_manage."""
        config = AuthConfig(secret_key=SECRET)
        store = MemoryTokenStore()
        core = IntegrationAuth(dict(USERS), config=config, token_store=store)
        fast = FastAuth(core)

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(fast.password_auth_router())

        composite = (task_read & member_of) | admin_manage  # type: ignore[operator]

        @app.get("/composite")
        @fast.require(composite)
        async def composite_endpoint(ctx: AuthContext = Depends(fast.context)) -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"user": ctx.user.id}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Admin has admin_manage → passes via OR branch
            result = await login(client, "admin@test.com", "admin-pass")
            token = result["body"]["access_token"]
            resp = await client.get("/composite", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            # Editor has task_read and member_of org-1 → passes via AND branch
            result = await login(client, "editor@test.com", "editor-pass")
            token = result["body"]["access_token"]
            resp = await client.get("/composite", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

            # Viewer has task_read but NOT member_of → fails
            result = await login(client, "viewer@test.com", "viewer-pass")
            token = result["body"]["access_token"]
            resp = await client.get("/composite", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403


class TestAccessControlWithChecker:
    async def test_string_checker_with_registry(self) -> None:
        """Test AccessControl using a RoleRegistry with hierarchy."""
        config = AuthConfig(secret_key=SECRET)
        store = MemoryTokenStore()
        core = IntegrationAuth(dict(USERS), config=config, token_store=store)
        fast = FastAuth(core)

        registry = RoleRegistry()
        registry.role("viewer", ["task:read", "user:read"])
        registry.role("editor", ["task:read", "task:write", "user:read"], inherits=["viewer"])
        registry.role("admin", ["task:read", "task:write", "task:delete", "admin:manage"], inherits=["editor"])

        access = fast.access_control(registry=registry)

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(fast.password_auth_router())

        @app.get("/guarded", dependencies=[Depends(access.guard("task", "delete"))])
        async def delete_task() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
            return {"deleted": "yes"}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Admin can delete
            result = await login(client, "admin@test.com", "admin-pass")
            resp = await client.get("/guarded", headers={"Authorization": f"Bearer {result['body']['access_token']}"})
            assert resp.status_code == 200

            # Editor cannot delete
            result = await login(client, "editor@test.com", "editor-pass")
            resp = await client.get("/guarded", headers={"Authorization": f"Bearer {result['body']['access_token']}"})
            assert resp.status_code == 403
