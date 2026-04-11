"""Security tests for AuthContext authorization logic.

Validates that the context correctly enforces authentication state,
wildcard permission semantics, and empty permission/role/relation lists.
"""

from __future__ import annotations

from urauth.authz.primitives import Permission, Relation, RelationTuple, Role, match_permission
from urauth.context import AuthContext


class TestAnonymousContextIsNotAuthenticated:
    """Anonymous and unauthenticated contexts must report correctly."""

    def test_anonymous_context(self) -> None:
        ctx = AuthContext.anonymous()
        assert ctx.is_authenticated() is False

    def test_context_with_user_none(self) -> None:
        ctx = AuthContext(user=None)
        assert ctx.is_authenticated() is False

    def test_context_with_user_none_explicit_authenticated_true(self) -> None:
        """Even if _authenticated=True, user=None means not authenticated."""
        ctx = AuthContext(user=None, _authenticated=True)
        assert ctx.is_authenticated() is False

    def test_context_with_user_but_not_authenticated(self) -> None:
        ctx = AuthContext(user="alice", _authenticated=False)
        assert ctx.is_authenticated() is False

    def test_context_with_user_and_authenticated(self) -> None:
        ctx = AuthContext(user="alice", _authenticated=True)
        assert ctx.is_authenticated() is True


class TestWildcardPermissionGrants:
    """Wildcard '*' grants access to everything, 'resource:*' grants all actions on that resource."""

    def test_global_wildcard_grants_everything(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("*")],
        )
        assert ctx.has_permission("user:read") is True
        assert ctx.has_permission("doc:write") is True
        assert ctx.has_permission("anything:else") is True

    def test_resource_wildcard_grants_all_actions(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "*")],
        )
        assert ctx.has_permission("user:read") is True
        assert ctx.has_permission("user:write") is True
        assert ctx.has_permission("user:delete") is True

    def test_resource_wildcard_does_not_grant_different_resource(self) -> None:
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "*")],
        )
        assert ctx.has_permission("doc:read") is False
        assert ctx.has_permission("task:write") is False

    def test_wildcard_does_not_work_in_reverse(self) -> None:
        """Having 'user:read' should NOT match a target of '*'."""
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "read")],
        )
        # Checking if user has the global wildcard permission -- they don't
        assert ctx.has_permission("*") is False

    def test_action_wildcard_does_not_reverse_match(self) -> None:
        """Having 'user:read' does NOT mean has_permission('user:*') is True."""
        ctx = AuthContext(
            user="alice",
            permissions=[Permission("user", "read")],
        )
        # The context has "user:read", checking against "user:*" as target.
        # match_permission(pattern=user:read, target=user:*) --
        # pattern action is "read", target action is "*", so "read" != "*" -> False
        assert ctx.has_permission("user:*") is False


class TestMatchPermissionFunction:
    """Direct tests for the match_permission function."""

    def test_exact_match(self) -> None:
        assert match_permission("user:read", "user:read") is True

    def test_cross_separator_match(self) -> None:
        assert match_permission("user:read", "user.read") is True

    def test_global_wildcard_pattern(self) -> None:
        assert match_permission("*", "user:read") is True

    def test_resource_wildcard_pattern(self) -> None:
        assert match_permission("user:*", "user:read") is True

    def test_no_match(self) -> None:
        assert match_permission("user:read", "doc:write") is False

    def test_different_resource_same_action(self) -> None:
        assert match_permission("user:read", "doc:read") is False


class TestEmptyPermissionsRolesRelations:
    """Empty lists mean no checks pass."""

    def test_empty_permissions_denies_everything(self) -> None:
        ctx = AuthContext(user="alice", permissions=[])
        assert ctx.has_permission("user:read") is False
        assert ctx.has_permission("*") is False

    def test_empty_roles_denies_all_role_checks(self) -> None:
        ctx = AuthContext(user="alice", roles=[])
        assert ctx.has_role("admin") is False
        assert ctx.has_role("viewer") is False
        assert ctx.has_any_role("admin", "viewer") is False

    def test_empty_relations_denies_all_relation_checks(self) -> None:
        ctx = AuthContext(user="alice", relations=[])
        owner = Relation("doc", "owner")
        assert ctx.has_relation(owner, "readme") is False

    def test_role_check_with_role_object(self) -> None:
        admin = Role("admin")
        ctx = AuthContext(user="alice", roles=[admin])
        assert ctx.has_role("admin") is True
        assert ctx.has_role("viewer") is False

    def test_relation_check(self) -> None:
        owner = Relation("doc", "owner")
        rt = RelationTuple(relation=owner, object_id="readme", subject="alice")
        ctx = AuthContext(user="alice", relations=[rt])
        assert ctx.has_relation(owner, "readme") is True
        assert ctx.has_relation(owner, "other-doc") is False

    def test_relation_check_different_relation_type(self) -> None:
        owner = Relation("doc", "owner")
        viewer = Relation("doc", "viewer")
        rt = RelationTuple(relation=owner, object_id="readme", subject="alice")
        ctx = AuthContext(user="alice", relations=[rt])
        assert ctx.has_relation(viewer, "readme") is False


class TestCrossSeparatorPermissionMatch:
    """Cross-separator permission matching — different separators should still match."""

    def test_colon_matches_dot(self) -> None:
        assert match_permission("user:read", "user.read") is True

    def test_colon_matches_pipe(self) -> None:
        assert match_permission("user:read", "user|read") is True

    def test_hash_matches_colon(self) -> None:
        assert match_permission("user#read", "user:read") is True


class TestRelationChecks:
    """Additional relation and role checks on AuthContext."""

    def test_context_has_relation_finds_matching_tuple(self) -> None:
        owner = Relation("doc", "owner")
        rt = RelationTuple(relation=owner, object_id="readme", subject="alice")
        ctx = AuthContext(user="alice", relations=[rt])
        assert ctx.has_relation(owner, "readme") is True

    def test_different_relation_type_does_not_match(self) -> None:
        owner = Relation("doc", "owner")
        editor = Relation("doc", "editor")
        rt = RelationTuple(relation=owner, object_id="readme", subject="alice")
        ctx = AuthContext(user="alice", relations=[rt])
        assert ctx.has_relation(editor, "readme") is False

    def test_has_any_role_with_role_objects(self) -> None:
        admin = Role("admin")
        editor = Role("editor")
        viewer = Role("viewer")
        ctx = AuthContext(user="alice", roles=[admin, editor])
        assert ctx.has_any_role(admin, editor) is True
        assert ctx.has_any_role(viewer) is False
        assert ctx.has_any_role(viewer, admin) is True
