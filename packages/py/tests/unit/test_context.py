"""Tests for AuthContext."""

from __future__ import annotations

import pytest

from urauth.authz.primitives import Action, Permission, Relation, Resource, Role
from urauth.context import AuthContext

# ── Fixtures ────────────────────────────────────────────────────

read = Action("read")
write = Action("write")
delete = Action("delete")
invite = Action("invite")

user_res = Resource("user")
post_res = Resource("post")
org_res = Resource("organization")

can_read_users = Permission(user_res, read)
can_write_posts = Permission(post_res, write)
can_delete_posts = Permission(post_res, delete)
can_invite = Permission(org_res, invite)

owns_post = Relation("owner", post_res)
member_of = Relation("member", org_res)

viewer = Role("viewer", [can_read_users])
editor = Role("editor", [can_read_users, can_write_posts])
admin = Role("admin", [can_read_users, can_write_posts, can_delete_posts, can_invite])


class FakeUser:
    def __init__(self, id: str, email: str) -> None:
        self.id = id
        self.email = email


# ── Tests ───────────────────────────────────────────────────────


class TestAuthContext:
    @pytest.fixture
    def ctx(self) -> AuthContext:
        return AuthContext(
            user=FakeUser("1", "alice@test.com"),
            roles=[admin, editor],
            permissions=admin.permissions + editor.permissions,
            relations=[(owns_post, "42"), (member_of, "acme")],
        )

    def test_is_authenticated(self, ctx: AuthContext) -> None:
        assert ctx.is_authenticated() is True

    def test_anonymous_not_authenticated(self) -> None:
        ctx = AuthContext.anonymous()
        assert ctx.is_authenticated() is False
        assert ctx.user is None

    def test_none_user_not_authenticated(self) -> None:
        ctx = AuthContext(user=None, _authenticated=True)
        assert ctx.is_authenticated() is False

    # ── has_permission ──

    def test_has_permission_exact(self, ctx: AuthContext) -> None:
        assert ctx.has_permission(can_read_users) is True
        assert ctx.has_permission(can_write_posts) is True
        assert ctx.has_permission(can_delete_posts) is True

    def test_has_permission_string(self, ctx: AuthContext) -> None:
        assert ctx.has_permission("user:read") is True

    def test_has_permission_missing(self) -> None:
        ctx = AuthContext(user=FakeUser("1", "a"), permissions=[can_read_users])
        assert ctx.has_permission(can_write_posts) is False

    def test_has_permission_wildcard(self) -> None:
        Permission("*", "*")
        # We need to test the actual wildcard string "*"
        ctx = AuthContext(
            user=FakeUser("1", "a"),
            permissions=[Permission("user", "read")],
        )
        # Add a string-compatible wildcard
        ctx.permissions.append(Permission("all", "all"))  # type: ignore
        assert ctx.has_permission(Permission("all", "all")) is True

    def test_has_permission_resource_wildcard(self) -> None:
        # Simulate a "user:*" wildcard permission
        class WildcardPerm:
            def __str__(self) -> str:
                return "user:*"

        ctx = AuthContext(
            user=FakeUser("1", "a"),
            permissions=[WildcardPerm()],  # type: ignore
        )
        assert ctx.has_permission(Permission("user", "read")) is True
        assert ctx.has_permission(Permission("user", "write")) is True
        assert ctx.has_permission(Permission("post", "read")) is False

    def test_has_permission_global_wildcard(self) -> None:
        class GlobalWild:
            def __str__(self) -> str:
                return "*"

        ctx = AuthContext(
            user=FakeUser("1", "a"),
            permissions=[GlobalWild()],  # type: ignore
        )
        assert ctx.has_permission(can_read_users) is True
        assert ctx.has_permission(can_delete_posts) is True

    def test_has_permission_empty(self) -> None:
        ctx = AuthContext(user=FakeUser("1", "a"), permissions=[])
        assert ctx.has_permission(can_read_users) is False

    # ── has_role ──

    def test_has_role(self, ctx: AuthContext) -> None:
        assert ctx.has_role(admin) is True
        assert ctx.has_role(editor) is True
        assert ctx.has_role(viewer) is False

    def test_has_role_by_string(self, ctx: AuthContext) -> None:
        assert ctx.has_role("admin") is True
        assert ctx.has_role("viewer") is False

    def test_has_any_role(self, ctx: AuthContext) -> None:
        assert ctx.has_any_role(viewer, admin) is True
        assert ctx.has_any_role(viewer) is False

    # ── has_relation ──

    def test_has_relation(self, ctx: AuthContext) -> None:
        assert ctx.has_relation(owns_post, "42") is True
        assert ctx.has_relation(member_of, "acme") is True

    def test_has_relation_wrong_id(self, ctx: AuthContext) -> None:
        assert ctx.has_relation(owns_post, "99") is False

    def test_has_relation_wrong_relation(self, ctx: AuthContext) -> None:
        assert ctx.has_relation(member_of, "42") is False

    def test_has_relation_empty(self) -> None:
        ctx = AuthContext(user=FakeUser("1", "a"))
        assert ctx.has_relation(owns_post, "42") is False

    # ── path_params ──

    def test_path_params_with_request(self) -> None:
        class FakeRequest:
            def __init__(self) -> None:
                self.path_params = {"post_id": "42", "org_id": "acme"}

        ctx = AuthContext(user=FakeUser("1", "a"), request=FakeRequest())
        assert ctx.path_params == {"post_id": "42", "org_id": "acme"}

    def test_path_params_no_request(self) -> None:
        ctx = AuthContext(user=FakeUser("1", "a"))
        assert ctx.path_params == {}

    # ── anonymous factory ──

    def test_anonymous_with_request(self) -> None:
        req = object()
        ctx = AuthContext.anonymous(request=req)
        assert ctx.request is req
        assert ctx.is_authenticated() is False
        assert ctx.roles == []
        assert ctx.permissions == []
        assert ctx.relations == []
