"""Tests for the checker-based access control system."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from tests.conftest import FakeBackend, FakeUser
from urauth import Auth, AuthConfig
from urauth.authz.checker import (
    RoleExpandingChecker,
    StringChecker,
)
from urauth.authz.permission_enum import PermissionEnum
from urauth.authz.primitives import Action, Permission, Resource, Role
from urauth.authz.roles import RoleRegistry
from urauth.backends.memory import MemoryTokenStore
from urauth.context import AuthContext
from urauth.fastapi.auth import FastAuth
from urauth.fastapi.authz.access import AccessControl
from urauth.fastapi.exceptions import register_exception_handlers


@dataclass
class _User:
    id: str = "u1"


# ── Helpers ──────────────────────────────────────────────────────


def _make_ctx(
    *,
    roles: list[Role] | None = None,
    permissions: list[Permission] | None = None,
    scopes: dict[str, list[Permission]] | None = None,
) -> AuthContext:
    return AuthContext(
        user=_User(),
        roles=roles or [],
        permissions=permissions or [],
        scopes=scopes or {},
    )


def make_context_resolver(ctx: AuthContext) -> Callable[[Request], Any]:
    """Create a resolver that always returns the given context."""

    async def resolver(_request: Request) -> AuthContext:
        return ctx

    return resolver


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def admin_ctx() -> AuthContext:
    return _make_ctx(
        roles=[Role("admin")],
        permissions=[Permission("user", "read"), Permission("user", "write"), Permission("user", "delete")],
    )


@pytest.fixture
def viewer_ctx() -> AuthContext:
    return _make_ctx(
        roles=[Role("viewer")],
        permissions=[Permission("user", "read")],
    )


@pytest.fixture
def string_checker() -> StringChecker:
    return StringChecker()


@pytest.fixture
def role_checker() -> RoleExpandingChecker:
    return RoleExpandingChecker(
        role_permissions={
            "admin": {"user:read", "user:write", "user:delete"},
            "viewer": {"user:read"},
        },
        hierarchy={"admin": ["viewer"]},
    )


@pytest.fixture
def app_factory(string_checker: StringChecker) -> Callable[[AuthContext], FastAPI]:
    """Factory to create a FastAPI app with StringChecker access control."""

    def _create(ctx: AuthContext) -> FastAPI:
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=string_checker,
        )

        @app.get("/guard-read")
        @access.guard("user", "read")
        async def guard_read(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/guard-delete")
        @access.guard("user", "delete")
        async def guard_delete(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/depends-read", dependencies=[Depends(access.guard("user", "read"))])
        async def depends_read() -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/depends-delete", dependencies=[Depends(access.guard("user", "delete"))])
        async def depends_delete() -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/check-delete")
        async def check_delete(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            can_delete = await access.check("user", "delete", request=request)
            return {"can_delete": can_delete}

        return app

    return _create


@pytest.fixture
async def admin_client(
    app_factory: Callable[[AuthContext], FastAPI], admin_ctx: AuthContext
) -> AsyncIterator[AsyncClient]:
    app = app_factory(admin_ctx)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def viewer_client(
    app_factory: Callable[[AuthContext], FastAPI], viewer_ctx: AuthContext
) -> AsyncIterator[AsyncClient]:
    app = app_factory(viewer_ctx)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ── AccessControl integration tests (StringChecker) ─────────────


class TestAccessControlStringChecker:
    async def test_guard_allowed(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/guard-read")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    async def test_guard_denied(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/guard-delete")
        assert resp.status_code == 403

    async def test_depends_allowed(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/depends-read")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    async def test_depends_denied(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/depends-delete")
        assert resp.status_code == 403

    async def test_check_inline_true(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/check-delete")
        assert resp.status_code == 200
        assert resp.json() == {"can_delete": True}

    async def test_check_inline_false(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/check-delete")
        assert resp.status_code == 200
        assert resp.json() == {"can_delete": False}

    async def test_admin_can_read(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/guard-read")
        assert resp.status_code == 200

    async def test_viewer_can_read(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/guard-read")
        assert resp.status_code == 200

    async def test_admin_can_delete(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/guard-delete")
        assert resp.status_code == 200

    async def test_viewer_cannot_delete(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/guard-delete")
        assert resp.status_code == 403


# ── RoleExpandingChecker tests ──────────────────────────────────


class TestAccessControlRoleChecker:
    @pytest.fixture
    def role_app_factory(self, role_checker: RoleExpandingChecker) -> Callable[[AuthContext], FastAPI]:
        def _create(ctx: AuthContext) -> FastAPI:
            app = FastAPI()
            register_exception_handlers(app)
            access = AccessControl(
                context_resolver=make_context_resolver(ctx),
                checker=role_checker,
            )

            @app.get("/guard-read")
            @access.guard("user", "read")
            async def guard_read(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
                return {"ok": True}

            @app.get("/guard-delete")
            @access.guard("user", "delete")
            async def guard_delete(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
                return {"ok": True}

            return app

        return _create

    async def test_admin_can_read(self, role_app_factory: Callable[[AuthContext], FastAPI]) -> None:
        ctx = _make_ctx(roles=[Role("admin")])
        app = role_app_factory(ctx)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/guard-read")
            assert resp.status_code == 200

    async def test_admin_can_delete(self, role_app_factory: Callable[[AuthContext], FastAPI]) -> None:
        ctx = _make_ctx(roles=[Role("admin")])
        app = role_app_factory(ctx)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/guard-delete")
            assert resp.status_code == 200

    async def test_viewer_can_read(self, role_app_factory: Callable[[AuthContext], FastAPI]) -> None:
        ctx = _make_ctx(roles=[Role("viewer")])
        app = role_app_factory(ctx)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/guard-read")
            assert resp.status_code == 200

    async def test_viewer_cannot_delete(self, role_app_factory: Callable[[AuthContext], FastAPI]) -> None:
        ctx = _make_ctx(roles=[Role("viewer")])
        app = role_app_factory(ctx)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/guard-delete")
            assert resp.status_code == 403


# ── Custom checker protocol test ────────────────────────────────


class TestCustomChecker:
    async def test_custom_checker_protocol(self) -> None:
        class AlwaysAllow:
            async def has_permission(
                self, ctx: AuthContext, resource: str, action: str, **kwargs: Any
            ) -> bool:
                return True

        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(_make_ctx()),
            checker=AlwaysAllow(),
        )

        @app.get("/test")
        @access.guard("any", "thing")
        async def test_endpoint(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test")
            assert resp.status_code == 200

    async def test_custom_checker_deny(self) -> None:
        class AlwaysDeny:
            async def has_permission(
                self, ctx: AuthContext, resource: str, action: str, **kwargs: Any
            ) -> bool:
                return False

        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(_make_ctx()),
            checker=AlwaysDeny(),
        )

        @app.get("/test")
        @access.guard("any", "thing")
        async def test_endpoint(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test")
            assert resp.status_code == 403


# ── Scope tests ─────────────────────────────────────────────────


class TestScopeSupport:
    async def test_scope_from_path_param(self) -> None:
        ctx = _make_ctx(
            permissions=[],
            scopes={
                "org-1": [Permission("user", "read"), Permission("user", "delete")],
                "org-2": [Permission("user", "read")],
            },
        )
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.delete("/orgs/{org_id}/users/{user_id}")
        @access.guard("user", "delete", scope_from="org_id")
        async def delete_org_user(  # pyright: ignore[reportUnusedFunction]
            request: Request, org_id: str, user_id: str
        ) -> dict[str, bool]:
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.delete("/orgs/org-1/users/u2")
            assert resp.status_code == 200

            resp = await client.delete("/orgs/org-2/users/u2")
            assert resp.status_code == 403

    async def test_static_scope(self) -> None:
        ctx = _make_ctx(
            permissions=[],
            scopes={"tenant-a": [Permission("post", "read")]},
        )
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.get("/scoped")
        @access.guard("post", "read", scope="tenant-a")
        async def scoped_read(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/scoped")
            assert resp.status_code == 200


# ── Typed Permission guard() tests ──────────────────────────────


class TestTypedPermissionGuard:
    @pytest.fixture
    def perms(self) -> Any:
        user = Resource("user")
        task = Resource("task")
        read = Action("read")
        write = Action("write")
        delete = Action("delete")

        class P(PermissionEnum):
            USER_READ = (user, read)
            TASK_READ = (task, read)
            TASK_WRITE = (task, write)
            TASK_DELETE = (task, delete)

        return P

    async def test_guard_with_permission_enum_decorator(self, perms: Any) -> None:
        ctx = _make_ctx(permissions=[Permission("task", "read")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.get("/tasks")
        @access.guard(perms.TASK_READ)
        async def list_tasks(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/tasks")
            assert resp.status_code == 200

    async def test_guard_with_permission_enum_denied(self, perms: Any) -> None:
        ctx = _make_ctx(permissions=[Permission("task", "read")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.delete("/tasks/1")
        @access.guard(perms.TASK_DELETE)
        async def delete_task(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.delete("/tasks/1")
            assert resp.status_code == 403

    async def test_guard_with_permission_depends(self, perms: Any) -> None:
        ctx = _make_ctx(permissions=[Permission("task", "write")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.put("/tasks/1", dependencies=[Depends(access.guard(perms.TASK_WRITE))])
        async def update_task() -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put("/tasks/1")
            assert resp.status_code == 200

    async def test_guard_with_permission_depends_denied(self, perms: Any) -> None:
        ctx = _make_ctx(permissions=[Permission("task", "read")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.put("/tasks/1", dependencies=[Depends(access.guard(perms.TASK_WRITE))])
        async def update_task() -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.put("/tasks/1")
            assert resp.status_code == 403

    async def test_guard_with_raw_permission_object(self) -> None:
        ctx = _make_ctx(permissions=[Permission("doc", "read")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        perm = Permission("doc", "read")

        @app.get("/docs")
        @access.guard(perm)
        async def list_docs(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/docs")
            assert resp.status_code == 200

    async def test_check_with_permission_enum(self, perms: Any) -> None:
        ctx = _make_ctx(permissions=[Permission("task", "read")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=StringChecker(),
        )

        @app.get("/check")
        async def check_endpoint(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            can_read = await access.check(perms.TASK_READ, request=request)
            can_write = await access.check(perms.TASK_WRITE, request=request)
            return {"can_read": can_read, "can_write": can_write}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/check")
            assert resp.status_code == 200
            assert resp.json() == {"can_read": True, "can_write": False}

    async def test_permission_kwarg_passed_to_checker(self) -> None:
        """guard() passes the original Permission object to checker as permission= kwarg."""
        received_permission = None

        class CapturingChecker:
            async def has_permission(
                self, ctx: AuthContext, resource: str, action: str, **kwargs: Any
            ) -> bool:
                nonlocal received_permission
                received_permission = kwargs.get("permission")
                return True

        perm = Permission("doc", "edit")
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(_make_ctx()),
            checker=CapturingChecker(),
        )

        @app.get("/test")
        @access.guard(perm)
        async def test_endpoint(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/test")
            assert received_permission is perm


# ── RoleRegistry-based access control test ──────────────────────


class TestRoleRegistryAccessControl:
    async def test_registry_based_guard(self) -> None:
        class P(PermissionEnum):
            TASK_READ = ("task", "read")
            TASK_WRITE = ("task", "write")

        registry = RoleRegistry()
        registry.role("editor", permissions=[P.TASK_READ, P.TASK_WRITE])
        registry.role("viewer", permissions=[P.TASK_READ])

        ctx = _make_ctx(roles=[Role("editor")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=registry.build_checker(),
        )

        @app.get("/tasks")
        @access.guard(P.TASK_READ)
        async def list_tasks(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.post("/tasks")
        @access.guard(P.TASK_WRITE)
        async def create_task(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/tasks")
            assert resp.status_code == 200

            resp = await client.post("/tasks")
            assert resp.status_code == 200

    async def test_registry_viewer_denied(self) -> None:
        class P(PermissionEnum):
            TASK_READ = ("task", "read")
            TASK_WRITE = ("task", "write")

        registry = RoleRegistry()
        registry.role("viewer", permissions=[P.TASK_READ])

        ctx = _make_ctx(roles=[Role("viewer")])
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl(
            context_resolver=make_context_resolver(ctx),
            checker=registry.build_checker(),
        )

        @app.post("/tasks")
        @access.guard(P.TASK_WRITE)
        async def create_task(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/tasks")
            assert resp.status_code == 403


# ── FastAuth.access_control() integration test ──────────────────


class _TestBackendAuth(Auth):
    def __init__(self, backend: FakeBackend, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._backend = backend

    async def get_user(self, user_id: Any) -> Any | None:
        return await self._backend.get_by_id(str(user_id))

    async def get_user_by_username(self, username: str) -> Any | None:
        return await self._backend.get_by_username(username)

    async def verify_password(self, user: Any, password: str) -> bool:  # type: ignore[override]
        return await self._backend.verify_password(user, password)


class TestFastAuthAccessControl:
    @pytest.fixture
    def alice(self) -> FakeUser:
        return FakeUser(
            id="user-1",
            email="alice@example.com",
            roles=["admin"],
            password_hash="secret123",
        )

    @pytest.fixture
    def bob(self) -> FakeUser:
        return FakeUser(
            id="user-2",
            email="bob@example.com",
            roles=["viewer"],
            password_hash="password456",
        )

    @pytest.fixture
    def app(self, alice: FakeUser, bob: FakeUser) -> FastAPI:
        backend = FakeBackend([alice, bob])
        config = AuthConfig(secret_key="access-control-integration-test-key")
        token_store = MemoryTokenStore()
        core = _TestBackendAuth(backend, config=config, token_store=token_store)
        auth = FastAuth(core)

        checker = RoleExpandingChecker(
            role_permissions={
                "admin": {"user:read", "user:write", "user:delete"},
                "viewer": {"user:read"},
            },
            hierarchy={"admin": ["viewer"]},
        )
        access = auth.access_control(checker=checker)

        app = FastAPI(lifespan=auth.lifespan())
        auth.init_app(app)
        app.include_router(auth.password_auth_router())

        @app.get("/policy-delete")
        @access.guard("user", "delete")
        async def policy_delete(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/policy-read")
        @access.guard("user", "read")
        async def policy_read(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        return app

    @pytest.fixture
    async def client(self, app: FastAPI) -> AsyncIterator[AsyncClient]:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_admin_can_delete(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={"username": "alice@example.com", "password": "secret123"},
        )
        token = login_resp.json()["access_token"]

        resp = await client.get("/policy-delete", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_viewer_cannot_delete(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={"username": "bob@example.com", "password": "password456"},
        )
        token = login_resp.json()["access_token"]

        resp = await client.get("/policy-delete", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    async def test_viewer_can_read(self, client: AsyncClient) -> None:
        login_resp = await client.post(
            "/auth/login",
            json={"username": "bob@example.com", "password": "password456"},
        )
        token = login_resp.json()["access_token"]

        resp = await client.get("/policy-read", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_registry_based_access_control(self, alice: FakeUser, bob: FakeUser) -> None:
        """Test FastAuth.access_control(registry=...) integration."""
        backend = FakeBackend([alice, bob])
        config = AuthConfig(secret_key="registry-integration-test-key")
        token_store = MemoryTokenStore()
        core = _TestBackendAuth(backend, config=config, token_store=token_store)
        auth = FastAuth(core)

        registry = RoleRegistry()
        registry.role("admin", permissions=["user:read", "user:write", "user:delete"])
        registry.role("viewer", permissions=["user:read"])
        registry.role("admin", permissions=["user:read", "user:write", "user:delete"], inherits=["viewer"])

        access = auth.access_control(registry=registry)

        app = FastAPI(lifespan=auth.lifespan())
        auth.init_app(app)
        app.include_router(auth.password_auth_router())

        @app.get("/delete")
        @access.guard("user", "delete")
        async def policy_delete(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            login_resp = await client.post(
                "/auth/login",
                json={"username": "alice@example.com", "password": "secret123"},
            )
            token = login_resp.json()["access_token"]

            resp = await client.get("/delete", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
