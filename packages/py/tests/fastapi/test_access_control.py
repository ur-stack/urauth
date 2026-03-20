"""Tests for the access control system (RBAC, ABAC, PBAC, ReBAC, combined, grants, AccessControl)."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from enum import Enum

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from urauth import AuthConfig
from urauth.authz import AccessContext, Subject
from urauth.authz.exceptions import ConfigurationError, PolicyEvaluationError
from urauth.authz.grants import PermissionSet
from urauth.authz.policy import (
    ABACPolicy,
    ABACRule,
    AllOf,
    AnyOf,
    Condition,
    Effect,
    NotPolicy,
    PBACPolicy,
    PolicyStatement,
    RBACPolicy,
    ReBACPolicy,
)
from urauth.authz.policy.abac import Operator
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAPIAuth
from urauth.fastapi.authz.access import AccessControl
from urauth.fastapi.exceptions import register_exception_handlers

from ..conftest import FakeBackend, FakeUser

# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def admin_subject() -> Subject:
    return Subject(
        id="admin-1",
        roles=["admin"],
        permissions=[],
        attributes={"department": "engineering", "level": 10},
        relationships={"owner": {"document:123"}},
    )


@pytest.fixture
def viewer_subject() -> Subject:
    return Subject(
        id="viewer-1",
        roles=["viewer"],
        permissions=[],
        attributes={"department": "marketing", "level": 3},
        relationships={"viewer": {"document:123"}},
    )


@pytest.fixture
def rbac_policy() -> RBACPolicy:
    rbac = RBACPolicy()
    rbac.grant("admin", "read", "write", "delete")
    rbac.grant("viewer", "read")
    rbac.inherit("admin", "viewer")
    return rbac


def make_subject_resolver(subject: Subject) -> Callable[[Request], object]:
    """Create a resolver that always returns the given subject."""

    async def resolver(_request: Request) -> Subject:
        return subject

    return resolver


@pytest.fixture
def app_factory(rbac_policy: RBACPolicy) -> Callable[[Subject], FastAPI]:
    """Factory to create a FastAPI app with access control for a given subject."""

    def _create(subject: Subject) -> FastAPI:
        app = FastAPI()
        register_exception_handlers(app)
        access = AccessControl[str, str, str](
            policy=rbac_policy,
            subject_resolver=make_subject_resolver(subject),
        )

        @app.get("/guard-read")
        @access.guard("read")
        async def guard_read(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/guard-delete")
        @access.guard("delete")
        async def guard_delete(_request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            return {"ok": True}

        @app.get("/require-read")
        async def require_read(  # pyright: ignore[reportUnusedFunction]
            allowed: bool = Depends(access.require("read")),  # pyright: ignore[reportCallInDefaultInitializer, reportAny]
        ) -> dict[str, bool]:
            return {"allowed": allowed}

        @app.get("/require-delete")
        async def require_delete(  # pyright: ignore[reportUnusedFunction]
            allowed: bool = Depends(access.require("delete")),  # pyright: ignore[reportCallInDefaultInitializer, reportAny]
        ) -> dict[str, bool]:
            return {"allowed": allowed}

        @app.get("/check-delete")
        async def check_delete(request: Request) -> dict[str, bool]:  # pyright: ignore[reportUnusedFunction]
            can_delete = await access.check("delete", request=request)
            return {"can_delete": can_delete}

        return app

    return _create


@pytest.fixture
async def admin_client(app_factory: Callable[[Subject], FastAPI], admin_subject: Subject) -> AsyncIterator[AsyncClient]:
    app = app_factory(admin_subject)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def viewer_client(
    app_factory: Callable[[Subject], FastAPI], viewer_subject: Subject
) -> AsyncIterator[AsyncClient]:
    app = app_factory(viewer_subject)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ── AccessControl integration tests ────────────────────────────


class TestAccessControl:
    async def test_guard_allowed(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/guard-read")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    async def test_guard_denied(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/guard-delete")
        assert resp.status_code == 403

    async def test_require_allowed(self, admin_client: AsyncClient) -> None:
        resp = await admin_client.get("/require-read")
        assert resp.status_code == 200
        assert resp.json() == {"allowed": True}

    async def test_require_denied(self, viewer_client: AsyncClient) -> None:
        resp = await viewer_client.get("/require-delete")
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


# ── RBACPolicy unit tests ──────────────────────────────────────


class TestRBACPolicy:
    @pytest.fixture
    def rbac(self) -> RBACPolicy:
        policy = RBACPolicy()
        policy.grant("admin", "read", "write", "delete")
        policy.grant("editor", "read", "write")
        policy.grant("viewer", "read")
        return policy

    async def test_basic_grant(self, rbac: RBACPolicy) -> None:
        subject = Subject(id="u1", roles=["admin"])
        ctx = AccessContext(subject=subject, action="delete")
        assert await rbac.evaluate(ctx) is True

    async def test_deny_missing_permission(self, rbac: RBACPolicy) -> None:
        subject = Subject(id="u1", roles=["viewer"])
        ctx = AccessContext(subject=subject, action="write")
        assert await rbac.evaluate(ctx) is False

    async def test_role_hierarchy(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("admin", "delete")
        rbac.grant("viewer", "read")
        rbac.inherit("admin", "viewer")

        subject = Subject(id="u1", roles=["admin"])
        ctx = AccessContext(subject=subject, action="read")
        assert await rbac.evaluate(ctx) is True

    async def test_deep_hierarchy(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("superadmin", "nuke")
        rbac.grant("admin", "delete")
        rbac.grant("viewer", "read")
        rbac.inherit("superadmin", "admin")
        rbac.inherit("admin", "viewer")

        subject = Subject(id="u1", roles=["superadmin"])
        assert await rbac.evaluate(AccessContext(subject=subject, action="read")) is True
        assert await rbac.evaluate(AccessContext(subject=subject, action="delete")) is True
        assert await rbac.evaluate(AccessContext(subject=subject, action="nuke")) is True

    async def test_multiple_roles(self, rbac: RBACPolicy) -> None:
        subject = Subject(id="u1", roles=["viewer", "editor"])
        ctx = AccessContext(subject=subject, action="write")
        assert await rbac.evaluate(ctx) is True

    async def test_no_action_always_allowed(self, rbac: RBACPolicy) -> None:
        subject = Subject(id="u1", roles=["viewer"])
        ctx = AccessContext(subject=subject, action=None)
        assert await rbac.evaluate(ctx) is True

    async def test_direct_permissions(self) -> None:
        rbac = RBACPolicy()
        subject = Subject(id="u1", roles=[], permissions=["special"])
        ctx = AccessContext(subject=subject, action="special")
        assert await rbac.evaluate(ctx) is True

    def test_cycle_detection(self) -> None:
        rbac = RBACPolicy()
        rbac.inherit("a", "b")
        with pytest.raises(ConfigurationError, match="Cycle"):
            rbac.inherit("b", "a")

    def test_self_inherit(self) -> None:
        rbac = RBACPolicy()
        with pytest.raises(ConfigurationError, match="cannot inherit from itself"):
            rbac.inherit("a", "a")

    async def test_unknown_role(self, rbac: RBACPolicy) -> None:
        subject = Subject(id="u1", roles=["nonexistent"])
        ctx = AccessContext(subject=subject, action="read")
        assert await rbac.evaluate(ctx) is False

    def test_fluent_chaining(self) -> None:
        rbac = RBACPolicy()
        result = rbac.grant("admin", "read").grant("admin", "write").inherit("admin", "viewer")
        assert result is rbac


# ── ABACPolicy unit tests ──────────────────────────────────────


class TestABACPolicy:
    async def test_equality_rule(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")

        subject = Subject(id="u1", attributes={"department": "engineering"})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

        subject2 = Subject(id="u2", attributes={"department": "marketing"})
        assert await abac.evaluate(AccessContext(subject=subject2)) is False

    async def test_not_equals(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.department").not_equals("marketing")

        subject = Subject(id="u1", attributes={"department": "engineering"})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

    async def test_in_operator(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.department").in_(["engineering", "product"])

        subject = Subject(id="u1", attributes={"department": "engineering"})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

        subject2 = Subject(id="u2", attributes={"department": "marketing"})
        assert await abac.evaluate(AccessContext(subject=subject2)) is False

    async def test_contains_operator(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.tags").contains("vip")

        subject = Subject(id="u1", attributes={"tags": ["vip", "early-adopter"]})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

    async def test_comparison_operators(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.level").gte(5)

        subject = Subject(id="u1", attributes={"level": 10})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

        subject2 = Subject(id="u2", attributes={"level": 3})
        assert await abac.evaluate(AccessContext(subject=subject2)) is False

    async def test_regex_matches(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.email").matches(r"@example\.com$")

        subject = Subject(id="u1", attributes={"email": "user@example.com"})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

        subject2 = Subject(id="u2", attributes={"email": "user@other.com"})
        assert await abac.evaluate(AccessContext(subject=subject2)) is False

    async def test_multiple_rules_all(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")
        abac.when("subject.attributes.level").gte(5)

        subject = Subject(id="u1", attributes={"department": "engineering", "level": 10})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

        subject2 = Subject(id="u2", attributes={"department": "engineering", "level": 3})
        assert await abac.evaluate(AccessContext(subject=subject2)) is False

    async def test_multiple_rules_any(self) -> None:
        abac = ABACPolicy(match_any=True)
        abac.when("subject.attributes.department").equals("engineering")
        abac.when("subject.attributes.level").gte(5)

        subject = Subject(id="u1", attributes={"department": "engineering", "level": 3})
        assert await abac.evaluate(AccessContext(subject=subject)) is True

    async def test_no_rules_allows(self) -> None:
        abac = ABACPolicy()
        subject = Subject(id="u1")
        assert await abac.evaluate(AccessContext(subject=subject)) is True

    async def test_missing_attribute_raises(self) -> None:
        abac = ABACPolicy()
        abac.when("subject.attributes.nonexistent").equals("x")

        subject = Subject(id="u1", attributes={})
        with pytest.raises(PolicyEvaluationError, match="nonexistent"):
            await abac.evaluate(AccessContext(subject=subject))

    async def test_add_rule_directly(self) -> None:
        abac = ABACPolicy()
        abac.add_rule(ABACRule("subject.id", Operator.EQ, "admin-1"))

        subject = Subject(id="admin-1")
        assert await abac.evaluate(AccessContext(subject=subject)) is True


# ── PBACPolicy unit tests ──────────────────────────────────────


class TestPBACPolicy:
    @pytest.fixture
    def subject(self) -> Subject:
        return Subject(id="u1", attributes={"department": "engineering"})

    async def test_basic_allow(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(actions=["read", "write"], resources=["document:*"])

        ctx = AccessContext(subject=subject, action="read", resource="document:123")
        assert await pbac.evaluate(ctx) is True

    async def test_no_matching_statement(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(actions=["read"], resources=["document:*"])

        ctx = AccessContext(subject=subject, action="delete", resource="document:123")
        assert await pbac.evaluate(ctx) is False

    async def test_deny_overrides_allow(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(actions=["*"], resources=["*"])
        pbac.deny(actions=["delete"], resources=["*"])

        ctx = AccessContext(subject=subject, action="delete", resource="document:123")
        assert await pbac.evaluate(ctx) is False

        ctx2 = AccessContext(subject=subject, action="read", resource="document:123")
        assert await pbac.evaluate(ctx2) is True

    async def test_resource_glob_matching(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(actions=["read"], resources=["document:*"])

        assert await pbac.evaluate(AccessContext(subject=subject, action="read", resource="document:456")) is True

        assert await pbac.evaluate(AccessContext(subject=subject, action="read", resource="user:456")) is False

    async def test_action_glob_matching(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(actions=["doc:*"], resources=["*"])

        assert await pbac.evaluate(AccessContext(subject=subject, action="doc:read", resource="any")) is True

        assert await pbac.evaluate(AccessContext(subject=subject, action="user:read", resource="any")) is False

    async def test_conditions(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(
            actions=["read"],
            resources=["*"],
            conditions=[
                Condition("subject.attributes.department", Operator.EQ, "engineering"),
            ],
        )

        assert await pbac.evaluate(AccessContext(subject=subject, action="read", resource="any")) is True

        other = Subject(id="u2", attributes={"department": "marketing"})
        assert await pbac.evaluate(AccessContext(subject=other, action="read", resource="any")) is False

    async def test_deny_with_condition(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.allow(actions=["*"], resources=["*"])
        pbac.deny(
            actions=["delete"],
            resources=["*"],
            conditions=[
                Condition("subject.attributes.department", Operator.NEQ, "engineering"),
            ],
        )

        ctx = AccessContext(subject=subject, action="delete", resource="any")
        assert await pbac.evaluate(ctx) is True

        marketing = Subject(id="u2", attributes={"department": "marketing"})
        ctx2 = AccessContext(subject=marketing, action="delete", resource="any")
        assert await pbac.evaluate(ctx2) is False

    async def test_fluent_api(self) -> None:
        pbac = PBACPolicy()
        result = pbac.allow(actions=["read"]).deny(actions=["delete"])
        assert result is pbac

    async def test_add_statement_directly(self, subject: Subject) -> None:
        pbac = PBACPolicy()
        pbac.add_statement(
            PolicyStatement(
                effect=Effect.ALLOW,
                actions=["read"],
                resources=["*"],
            )
        )
        assert await pbac.evaluate(AccessContext(subject=subject, action="read", resource="any")) is True


# ── ReBACPolicy unit tests ─────────────────────────────────────


class TestReBACPolicy:
    async def test_basic_relation(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("owner")

        subject = Subject(id="u1", relationships={"owner": {"document:123"}})
        ctx = AccessContext(subject=subject, resource="document:123")
        assert await rebac.evaluate(ctx) is True

    async def test_no_relation(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("owner")

        subject = Subject(id="u1", relationships={})
        ctx = AccessContext(subject=subject, resource="document:123")
        assert await rebac.evaluate(ctx) is False

    async def test_wrong_resource(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("owner")

        subject = Subject(id="u1", relationships={"owner": {"document:123"}})
        ctx = AccessContext(subject=subject, resource="document:999")
        assert await rebac.evaluate(ctx) is False

    async def test_relation_implication(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("viewer")
        rebac.imply("owner", "editor").imply("editor", "viewer")

        subject = Subject(id="u1", relationships={"owner": {"document:123"}})
        ctx = AccessContext(subject=subject, resource="document:123")
        assert await rebac.evaluate(ctx) is True

    async def test_resource_type_filter(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("owner", resource_type="document")

        subject = Subject(id="u1", relationships={"owner": {"document:123", "folder:1"}})

        ctx1 = AccessContext(subject=subject, resource="document:123")
        assert await rebac.evaluate(ctx1) is True

        ctx2 = AccessContext(subject=subject, resource="folder:1")
        assert await rebac.evaluate(ctx2) is False

    async def test_no_resource(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("owner")

        subject = Subject(id="u1", relationships={"owner": {"document:123"}})
        ctx = AccessContext(subject=subject, resource=None)
        assert await rebac.evaluate(ctx) is False

    async def test_no_rules_allows(self) -> None:
        rebac = ReBACPolicy()
        subject = Subject(id="u1")
        ctx = AccessContext(subject=subject, resource="document:123")
        assert await rebac.evaluate(ctx) is True

    def test_cycle_detection(self) -> None:
        rebac = ReBACPolicy()
        rebac.imply("a", "b")
        with pytest.raises(ConfigurationError, match="Cycle"):
            rebac.imply("b", "a")

    def test_self_implication(self) -> None:
        rebac = ReBACPolicy()
        with pytest.raises(ConfigurationError, match="cannot imply itself"):
            rebac.imply("a", "a")

    async def test_multiple_relations(self) -> None:
        rebac = ReBACPolicy()
        rebac.allow_if("owner")
        rebac.allow_if("editor")

        subject = Subject(id="u1", relationships={"editor": {"document:123"}})
        ctx = AccessContext(subject=subject, resource="document:123")
        assert await rebac.evaluate(ctx) is True


# ── Combined policy tests ──────────────────────────────────────


class TestCombinedPolicies:
    async def test_allof_all_pass(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("admin", "read")
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")

        policy = AllOf(rbac, abac)
        subject = Subject(id="u1", roles=["admin"], attributes={"department": "engineering"})
        ctx = AccessContext(subject=subject, action="read")
        assert await policy.evaluate(ctx) is True

    async def test_allof_one_fails(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("admin", "read")
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")

        policy = AllOf(rbac, abac)
        subject = Subject(id="u1", roles=["admin"], attributes={"department": "marketing"})
        ctx = AccessContext(subject=subject, action="read")
        assert await policy.evaluate(ctx) is False

    async def test_anyof_one_passes(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("admin", "read")
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")

        policy = AnyOf(rbac, abac)
        subject = Subject(id="u1", roles=["viewer"], attributes={"department": "engineering"})
        ctx = AccessContext(subject=subject, action="read")
        assert await policy.evaluate(ctx) is True

    async def test_anyof_none_pass(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("admin", "delete")
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")

        policy = AnyOf(rbac, abac)
        subject = Subject(id="u1", roles=["viewer"], attributes={"department": "marketing"})
        ctx = AccessContext(subject=subject, action="delete")
        assert await policy.evaluate(ctx) is False

    async def test_not_policy(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("banned", "access")

        policy = NotPolicy(rbac)
        subject = Subject(id="u1", roles=["banned"])
        ctx = AccessContext(subject=subject, action="access")
        assert await policy.evaluate(ctx) is False

        subject2 = Subject(id="u2", roles=["regular"])
        ctx2 = AccessContext(subject=subject2, action="access")
        assert await policy.evaluate(ctx2) is True

    async def test_nested_combinators(self) -> None:
        rbac = RBACPolicy()
        rbac.grant("admin", "delete")
        abac = ABACPolicy()
        abac.when("subject.attributes.level").gte(5)
        abac2 = ABACPolicy()
        abac2.when("subject.attributes.department").equals("engineering")

        # Must be admin AND (level >= 5 OR engineering department)
        policy = AllOf(rbac, AnyOf(abac, abac2))

        subject = Subject(
            id="u1",
            roles=["admin"],
            attributes={"level": 3, "department": "engineering"},
        )
        ctx = AccessContext(subject=subject, action="delete")
        assert await policy.evaluate(ctx) is True

        subject2 = Subject(
            id="u2",
            roles=["admin"],
            attributes={"level": 3, "department": "marketing"},
        )
        ctx2 = AccessContext(subject=subject2, action="delete")
        assert await policy.evaluate(ctx2) is False


# ── PermissionSet tests ────────────────────────────────────────


class Perm(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


class TestPermissionSet:
    def test_from_enum(self) -> None:
        ps = PermissionSet.from_enum(Perm)
        assert "read" in ps
        assert "write" in ps
        assert "delete" in ps
        assert "admin" not in ps
        assert len(ps) == 3

    def test_from_list(self) -> None:
        ps = PermissionSet.from_list(["read", "write"])
        assert "read" in ps
        assert "write" in ps
        assert "delete" not in ps

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_PERMS", "read, write , delete")
        ps = PermissionSet.from_env("TEST_PERMS")
        assert "read" in ps
        assert "write" in ps
        assert "delete" in ps
        assert len(ps) == 3

    def test_from_env_missing(self) -> None:
        ps = PermissionSet.from_env("NONEXISTENT_VAR_12345")
        assert len(ps) == 0

    def test_from_env_custom_separator(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_PERMS2", "read|write|delete")
        ps = PermissionSet.from_env("TEST_PERMS2", separator="|")
        assert "read" in ps
        assert len(ps) == 3

    async def test_from_db_sync(self) -> None:
        def loader() -> list[str]:
            return ["read", "write"]

        ps = await PermissionSet.from_db(loader)
        assert "read" in ps
        assert "write" in ps

    async def test_from_db_async(self) -> None:
        async def loader() -> list[str]:
            return ["read", "write"]

        ps = await PermissionSet.from_db(loader)
        assert "read" in ps
        assert "write" in ps

    def test_to_set(self) -> None:
        ps = PermissionSet.from_list(["read", "write"])
        s = ps.to_set()
        assert s == {"read", "write"}

    def test_iter(self) -> None:
        ps = PermissionSet.from_list(["read", "write"])
        assert set(ps) == {"read", "write"}

    def test_repr(self) -> None:
        ps = PermissionSet.from_list(["read"])
        assert "PermissionSet" in repr(ps)


# ── FastAPIAuth.access_control() integration test ──────────────


class TestFastAPIAuthAccessControl:
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
        auth = FastAPIAuth(backend, config, token_store=token_store)

        # Create a policy that requires "delete" permission for admin role
        rbac = RBACPolicy()
        rbac.grant("admin", "read", "write", "delete")
        rbac.grant("viewer", "read")

        access = auth.access_control(rbac)

        app = FastAPI(lifespan=auth.lifespan())
        auth.init_app(app)
        app.include_router(auth.password_auth_router())

        @app.get("/policy-delete")
        @access.guard("delete")
        async def policy_delete(request: Request) -> dict[str, bool]:
            return {"ok": True}

        @app.get("/policy-read")
        @access.guard("read")
        async def policy_read(request: Request) -> dict[str, bool]:
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
