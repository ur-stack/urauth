"""Authorization edge cases — permission matching, relation evaluation, composite requirements."""

from __future__ import annotations

import pytest

from urauth.authz.primitives import (
    Permission,
    Relation,
    RelationTuple,
    Role,
    match_permission,
)
from urauth.context import AuthContext

# ── Wildcard permission matching ──────────────────────────────


class TestWildcardPermissionMatching:
    def test_global_wildcard_matches_anything(self) -> None:
        assert match_permission("*", "user:read") is True
        assert match_permission("*", "admin:delete") is True
        assert match_permission("*", "*") is True

    def test_resource_wildcard(self) -> None:
        assert match_permission("user:*", "user:read") is True
        assert match_permission("user:*", "user:write") is True
        assert match_permission("user:*", "admin:read") is False

    def test_exact_match(self) -> None:
        assert match_permission("user:read", "user:read") is True
        assert match_permission("user:read", "user:write") is False

    def test_resource_star_matches_all(self) -> None:
        """*:read matches anything because resource='*' is a global wildcard."""
        assert match_permission("*:read", "user:read") is True

    def test_empty_strings(self) -> None:
        with pytest.raises(ValueError):
            match_permission("", "")
        with pytest.raises(ValueError):
            match_permission("", "user:read")

    def test_no_separator_raises(self) -> None:
        with pytest.raises(ValueError):
            match_permission("admin", "admin")

    def test_custom_separator(self) -> None:
        assert match_permission("user.read", "user.read") is True
        assert match_permission("user.*", "user.read") is True


# ── Relation.evaluate ignores resource_id ─────────────────────


class TestRelationEvaluateResourceIdGap:
    """Relation.evaluate() checks if the relation type exists for ANY resource ID.

    This is by design for composite requirements, but users should be aware
    that evaluate() does NOT filter by specific resource_id.
    """

    def test_relation_evaluate_matches_any_resource_id(self) -> None:
        """Relation('post', 'owner') matches even if the context only has ownership of post#123."""
        owner = Relation("post", "owner")
        ctx = AuthContext(
            user={"id": "user-1"},
            relations=[RelationTuple(owner, "post-123")],  # Only owns post-123
        )
        # evaluate() returns True — it doesn't check which post
        assert owner.evaluate(ctx) is True

    def test_has_relation_checks_specific_resource_id(self) -> None:
        """AuthContext.has_relation() correctly checks the specific resource_id."""
        owner = Relation("post", "owner")
        ctx = AuthContext(
            user={"id": "user-1"},
            relations=[RelationTuple(owner, "post-123")],
        )
        assert ctx.has_relation(owner, "post-123") is True
        assert ctx.has_relation(owner, "post-999") is False

    def test_relation_evaluate_no_relations(self) -> None:
        owner = Relation("post", "owner")
        ctx = AuthContext(user={"id": "user-1"}, relations=[])
        assert owner.evaluate(ctx) is False

    def test_relation_evaluate_different_relation_type(self) -> None:
        owner = Relation("post", "owner")
        viewer = Relation("post", "viewer")
        ctx = AuthContext(
            user={"id": "user-1"},
            relations=[RelationTuple(viewer, "post-123")],
        )
        assert owner.evaluate(ctx) is False
        assert viewer.evaluate(ctx) is True


# ── Composite requirements ────────────────────────────────────


class TestCompositeRequirements:
    def test_simple_and(self) -> None:
        read = Permission("task", "read")
        write = Permission("task", "write")
        ctx = AuthContext(
            user={"id": "user-1"},
            permissions=[read, write],
        )
        assert (read & write).evaluate(ctx) is True

    def test_simple_or(self) -> None:
        read = Permission("task", "read")
        admin = Permission("admin", "manage")
        ctx = AuthContext(
            user={"id": "user-1"},
            permissions=[read],
        )
        assert (read | admin).evaluate(ctx) is True
        assert (admin | read).evaluate(ctx) is True

    def test_and_fails_if_one_missing(self) -> None:
        read = Permission("task", "read")
        write = Permission("task", "write")
        ctx = AuthContext(
            user={"id": "user-1"},
            permissions=[read],
        )
        assert (read & write).evaluate(ctx) is False

    def test_or_fails_if_all_missing(self) -> None:
        admin = Permission("admin", "manage")
        superadmin = Permission("super", "manage")
        ctx = AuthContext(
            user={"id": "user-1"},
            permissions=[],
        )
        assert (admin | superadmin).evaluate(ctx) is False

    def test_deeply_nested_composite(self) -> None:
        """(A & B) | (C & (D | E)) — complex nested requirement."""
        a = Permission("a", "read")
        b = Permission("b", "read")
        c = Permission("c", "read")
        d = Permission("d", "read")
        e = Permission("e", "read")

        composite = (a & b) | (c & (d | e))

        # Has a + b → True (first branch)
        ctx1 = AuthContext(user={"id": "u"}, permissions=[a, b])
        assert composite.evaluate(ctx1) is True

        # Has c + e → True (second branch, D|E satisfied by E)
        ctx2 = AuthContext(user={"id": "u"}, permissions=[c, e])
        assert composite.evaluate(ctx2) is True

        # Has c only → False (second branch needs D or E)
        ctx3 = AuthContext(user={"id": "u"}, permissions=[c])
        assert composite.evaluate(ctx3) is False

        # Has a only → False (first branch needs B)
        ctx4 = AuthContext(user={"id": "u"}, permissions=[a])
        assert composite.evaluate(ctx4) is False

    def test_mixed_permission_and_role(self) -> None:
        read = Permission("task", "read")
        admin_role = Role("admin")
        composite = read & admin_role

        ctx_both = AuthContext(
            user={"id": "u"},
            permissions=[read],
            roles=[admin_role],
        )
        assert composite.evaluate(ctx_both) is True

        ctx_perm_only = AuthContext(
            user={"id": "u"},
            permissions=[read],
            roles=[],
        )
        assert composite.evaluate(ctx_perm_only) is False

    def test_mixed_permission_and_relation(self) -> None:
        read = Permission("task", "read")
        owner = Relation("task", "owner")
        composite = read | owner

        # Has permission only
        ctx1 = AuthContext(user={"id": "u"}, permissions=[read])
        assert composite.evaluate(ctx1) is True

        # Has relation only
        ctx2 = AuthContext(user={"id": "u"}, relations=[RelationTuple(owner, "task-1")])
        assert composite.evaluate(ctx2) is True

        # Has neither
        ctx3 = AuthContext(user={"id": "u"})
        assert composite.evaluate(ctx3) is False


# ── Empty/duplicate permissions ───────────────────────────────


class TestEmptyAndDuplicatePermissions:
    def test_no_permissions_denies_all(self) -> None:
        ctx = AuthContext(user={"id": "u"}, permissions=[])
        assert ctx.has_permission(Permission("task", "read")) is False

    def test_no_roles_denies_role_check(self) -> None:
        ctx = AuthContext(user={"id": "u"}, roles=[])
        assert ctx.has_role(Role("admin")) is False

    def test_duplicate_permissions(self) -> None:
        read = Permission("task", "read")
        ctx = AuthContext(user={"id": "u"}, permissions=[read, read, read])
        assert ctx.has_permission(read) is True

    def test_duplicate_roles(self) -> None:
        admin = Role("admin")
        ctx = AuthContext(user={"id": "u"}, roles=[admin, admin])
        assert ctx.has_role(admin) is True
        assert ctx.has_any_role(admin) is True


# ── Permission string edge cases ─────────────────────────────


class TestPermissionStringEdgeCases:
    def test_single_string_without_separator_raises(self) -> None:
        with pytest.raises(ValueError, match="No separator found"):
            Permission("invalid")

    def test_multiple_separators_splits_on_first(self) -> None:
        """Permission('a:b:c') → resource='a', action='b:c'."""
        perm = Permission("a:b:c")
        assert str(perm.resource) == "a"
        assert str(perm.action) == "b:c"

    def test_empty_parts(self) -> None:
        """Permission(':') → resource='', action=''."""
        perm = Permission(":")
        assert str(perm.resource) == ""
        assert str(perm.action) == ""


# ── AuthContext.satisfies ─────────────────────────────────────


class TestAuthContextSatisfies:
    def test_satisfies_single_permission(self) -> None:
        read = Permission("task", "read")
        ctx = AuthContext(user={"id": "u"}, permissions=[read])
        assert ctx.satisfies(read) is True

    def test_satisfies_composite(self) -> None:
        read = Permission("task", "read")
        write = Permission("task", "write")
        ctx = AuthContext(user={"id": "u"}, permissions=[read])
        assert ctx.satisfies(read | write) is True
        assert ctx.satisfies(read & write) is False

    def test_anonymous_context_satisfies_nothing(self) -> None:
        ctx = AuthContext.anonymous()
        read = Permission("task", "read")
        assert ctx.satisfies(read) is False
        assert ctx.is_authenticated() is False


# ── Wildcard permissions on AuthContext ───────────────────────


class TestAuthContextWildcardPermissions:
    def test_global_wildcard_grants_everything(self) -> None:
        ctx = AuthContext(
            user={"id": "u"},
            permissions=[Permission("*", "placeholder")],  # resource="*" is a global wildcard
        )
        # resource="*" matches everything regardless of action
        assert ctx.has_permission(Permission("task", "read")) is True
        assert ctx.has_permission(Permission("admin", "delete")) is True

    def test_resource_wildcard_grants_all_actions(self) -> None:
        ctx = AuthContext(
            user={"id": "u"},
            permissions=[Permission("task", "*")],
        )
        assert ctx.has_permission(Permission("task", "read")) is True
        assert ctx.has_permission(Permission("task", "write")) is True
        assert ctx.has_permission(Permission("user", "read")) is False
