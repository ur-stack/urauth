"""Tests for tenant hierarchy primitives."""

from __future__ import annotations

import pytest

from urauth.tenant.hierarchy import TenantHierarchy, TenantLevel, TenantNode, TenantPath


class TestTenantLevel:
    def test_creation(self) -> None:
        level = TenantLevel("organization", 0)
        assert level.name == "organization"
        assert level.depth == 0

    def test_frozen(self) -> None:
        level = TenantLevel("organization", 0)
        with pytest.raises(AttributeError):
            level.name = "changed"  # type: ignore[misc]


class TestTenantNode:
    def test_creation(self) -> None:
        node = TenantNode("acme", "organization")
        assert node.id == "acme"
        assert node.level == "organization"

    def test_equality(self) -> None:
        a = TenantNode("acme", "organization")
        b = TenantNode("acme", "organization")
        assert a == b


class TestTenantPath:
    @pytest.fixture
    def path(self) -> TenantPath:
        return TenantPath([
            TenantNode("acme", "organization"),
            TenantNode("us-west", "region"),
            TenantNode("team-a", "group"),
        ])

    def test_leaf_id(self, path: TenantPath) -> None:
        assert path.leaf_id == "team-a"

    def test_leaf_level(self, path: TenantPath) -> None:
        assert path.leaf_level == "group"

    def test_id_at(self, path: TenantPath) -> None:
        assert path.id_at("organization") == "acme"
        assert path.id_at("region") == "us-west"
        assert path.id_at("group") == "team-a"
        assert path.id_at("nonexistent") is None

    def test_contains_self(self, path: TenantPath) -> None:
        assert path.contains(path)

    def test_contains_descendant(self, path: TenantPath) -> None:
        ancestor = TenantPath([TenantNode("acme", "organization")])
        assert ancestor.contains(path)

    def test_contains_not_ancestor(self, path: TenantPath) -> None:
        other = TenantPath([TenantNode("other-org", "organization")])
        assert not other.contains(path)

    def test_descendant_cannot_contain_ancestor(self, path: TenantPath) -> None:
        ancestor = TenantPath([TenantNode("acme", "organization")])
        assert not path.contains(ancestor)

    def test_is_descendant_of(self, path: TenantPath) -> None:
        assert path.is_descendant_of("acme")
        assert path.is_descendant_of("us-west")
        assert path.is_descendant_of("team-a")
        assert not path.is_descendant_of("nonexistent")

    def test_to_claim_roundtrip(self, path: TenantPath) -> None:
        claim = path.to_claim()
        assert claim == {"organization": "acme", "region": "us-west", "group": "team-a"}
        restored = TenantPath.from_claim(claim)
        assert restored.id_at("organization") == "acme"
        assert restored.id_at("region") == "us-west"
        assert restored.leaf_id == "team-a"

    def test_from_flat(self) -> None:
        path = TenantPath.from_flat("tenant-1")
        assert path.leaf_id == "tenant-1"
        assert path.leaf_level == "tenant"
        assert len(path) == 1

    def test_from_flat_custom_level(self) -> None:
        path = TenantPath.from_flat("org-1", level="organization")
        assert path.leaf_level == "organization"

    def test_len(self, path: TenantPath) -> None:
        assert len(path) == 3

    def test_iter(self, path: TenantPath) -> None:
        nodes = list(path)
        assert len(nodes) == 3
        assert nodes[0].level == "organization"
        assert nodes[2].level == "group"

    def test_repr(self, path: TenantPath) -> None:
        r = repr(path)
        assert "organization:acme" in r
        assert "group:team-a" in r


class TestTenantHierarchy:
    def test_from_strings(self) -> None:
        h = TenantHierarchy(["organization", "region", "group"])
        assert len(h) == 3
        assert h.depth_of("organization") == 0
        assert h.depth_of("region") == 1
        assert h.depth_of("group") == 2

    def test_from_levels(self) -> None:
        h = TenantHierarchy([
            TenantLevel("country", 0),
            TenantLevel("city", 1),
        ])
        assert len(h) == 2
        assert h.depth_of("country") == 0

    def test_parent_of(self) -> None:
        h = TenantHierarchy(["organization", "region", "group"])
        assert h.parent_of("organization") is None
        assert h.parent_of("region") == "organization"
        assert h.parent_of("group") == "region"

    def test_children_of(self) -> None:
        h = TenantHierarchy(["organization", "region", "group"])
        assert h.children_of("organization") == ["region"]
        assert h.children_of("region") == ["group"]
        assert h.children_of("group") == []

    def test_root_and_leaf(self) -> None:
        h = TenantHierarchy(["organization", "region", "group"])
        assert h.root.name == "organization"
        assert h.leaf.name == "group"

    def test_get(self) -> None:
        h = TenantHierarchy(["organization", "region"])
        assert h.get("organization") is not None
        assert h.get("nonexistent") is None

    def test_contains(self) -> None:
        h = TenantHierarchy(["organization", "region"])
        assert "organization" in h
        assert "nonexistent" not in h

    def test_getitem(self) -> None:
        h = TenantHierarchy(["organization", "region", "group"])
        assert h[0].name == "organization"
        assert h[2].name == "group"

    def test_iter(self) -> None:
        h = TenantHierarchy(["organization", "region"])
        names = [lvl.name for lvl in h]
        assert names == ["organization", "region"]

    def test_repr(self) -> None:
        h = TenantHierarchy(["organization", "region"])
        assert "organization → region" in repr(h)

    def test_unknown_level_raises(self) -> None:
        h = TenantHierarchy(["organization", "region"])
        with pytest.raises(KeyError):
            h.depth_of("nonexistent")
