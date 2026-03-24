"""Tests for all permission primitives: Action, Resource, Permission, Relation, Role."""

from __future__ import annotations

from urauth.authz.primitives import Action, Permission, Relation, Resource, Role

# ── Action ──────────────────────────────────────────────────────


class TestAction:
    def test_is_str_subclass(self) -> None:
        a = Action("read")
        assert isinstance(a, str)
        assert a == "read"

    def test_different_actions_not_equal(self) -> None:
        assert Action("read") != Action("write")

    def test_usable_in_set(self) -> None:
        s = {Action("read"), Action("write"), Action("read")}
        assert len(s) == 2

    def test_usable_as_dict_key(self) -> None:
        d = {Action("read"): 1}
        assert d[Action("read")] == 1


# ── Resource ────────────────────────────────────────────────────


class TestResource:
    def test_is_str_subclass(self) -> None:
        r = Resource("user")
        assert isinstance(r, str)
        assert r == "user"

    def test_different_resources_not_equal(self) -> None:
        assert Resource("user") != Resource("post")


# ── Permission ──────────────────────────────────────────────────


class TestPermission:
    def test_str_form(self) -> None:
        p = Permission("user", "read")
        assert str(p) == "user:read"

    def test_from_typed_primitives(self) -> None:
        p = Permission(Resource("user"), Action("read"))
        assert str(p) == "user:read"

    def test_eq_string(self) -> None:
        p = Permission("user", "read")
        assert p == "user:read"
        assert "user:read" == p  # noqa: SIM300

    def test_eq_permission(self) -> None:
        p1 = Permission("user", "read")
        p2 = Permission(Resource("user"), Action("read"))
        assert p1 == p2

    def test_ne(self) -> None:
        p = Permission("user", "read")
        assert p != "user:write"
        assert p != Permission("user", "write")
        assert p != Permission("post", "read")

    def test_ne_incompatible_type(self) -> None:
        p = Permission("user", "read")
        assert p != 42
        assert p.__eq__(42) is NotImplemented

    def test_hash_matches_str(self) -> None:
        p = Permission("user", "read")
        assert hash(p) == hash("user:read")

    def test_usable_in_set_with_strings(self) -> None:
        s = {Permission("user", "read"), "user:read"}
        assert len(s) == 1

    def test_repr(self) -> None:
        p = Permission("user", "read")
        r = repr(p)
        assert "user" in r
        assert "read" in r

    def test_resource_action_attributes(self) -> None:
        p = Permission(Resource("user"), Action("read"))
        assert isinstance(p.resource, Resource)
        assert isinstance(p.action, Action)
        assert p.resource == "user"
        assert p.action == "read"

    def test_auto_wraps_strings(self) -> None:
        p = Permission("user", "read")
        assert isinstance(p.resource, Resource)
        assert isinstance(p.action, Action)


# ── Relation ────────────────────────────────────────────────────


class TestRelation:
    def test_str_form(self) -> None:
        r = Relation("owner", "post")
        assert str(r) == "post#owner"

    def test_from_typed_resource(self) -> None:
        r = Relation("owner", Resource("post"))
        assert str(r) == "post#owner"

    def test_eq_relation(self) -> None:
        r1 = Relation("owner", "post")
        r2 = Relation("owner", Resource("post"))
        assert r1 == r2

    def test_eq_string(self) -> None:
        r = Relation("owner", "post")
        assert r == "post#owner"

    def test_ne(self) -> None:
        r = Relation("owner", "post")
        assert r != Relation("member", "post")
        assert r != Relation("owner", "org")
        assert r != "post#member"

    def test_ne_incompatible_type(self) -> None:
        r = Relation("owner", "post")
        assert r != 42
        assert r.__eq__(42) is NotImplemented

    def test_hash(self) -> None:
        r1 = Relation("owner", "post")
        r2 = Relation("owner", "post")
        assert hash(r1) == hash(r2)

    def test_usable_in_set(self) -> None:
        s = {Relation("owner", "post"), Relation("owner", "post"), Relation("member", "org")}
        assert len(s) == 2

    def test_repr(self) -> None:
        r = Relation("owner", "post")
        assert "owner" in repr(r)
        assert "post" in repr(r)

    def test_resource_attribute(self) -> None:
        r = Relation("owner", "post")
        assert isinstance(r.resource, Resource)
        assert r.name == "owner"


# ── Role ────────────────────────────────────────────────────────


class TestRole:
    def test_str_is_name(self) -> None:
        r = Role("admin")
        assert str(r) == "admin"

    def test_default_empty_permissions(self) -> None:
        r = Role("viewer")
        assert r.permissions == []

    def test_with_permissions(self) -> None:
        can_read = Permission("user", "read")
        can_write = Permission("user", "write")
        r = Role("editor", [can_read, can_write])
        assert len(r.permissions) == 2
        assert can_read in r.permissions

    def test_eq_role(self) -> None:
        r1 = Role("admin", [Permission("user", "read")])
        r2 = Role("admin", [Permission("post", "write")])
        # Equality is by name only
        assert r1 == r2

    def test_eq_string(self) -> None:
        r = Role("admin")
        assert r == "admin"

    def test_ne(self) -> None:
        assert Role("admin") != Role("viewer")
        assert Role("admin") != "viewer"

    def test_ne_incompatible_type(self) -> None:
        r = Role("admin")
        assert r != 42
        assert r.__eq__(42) is NotImplemented

    def test_hash(self) -> None:
        r1 = Role("admin")
        r2 = Role("admin")
        assert hash(r1) == hash(r2)

    def test_usable_in_set(self) -> None:
        s = {Role("admin"), Role("admin"), Role("viewer")}
        assert len(s) == 2

    def test_repr(self) -> None:
        r = Role("admin", [Permission("user", "read")])
        assert "admin" in repr(r)

    def test_permissions_list_is_copy(self) -> None:
        perms = [Permission("user", "read")]
        r = Role("admin", perms)
        perms.append(Permission("user", "write"))
        # Role's list should not be affected
        assert len(r.permissions) == 1
