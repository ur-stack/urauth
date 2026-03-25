"""Tenant hierarchy data structures.

Defines configurable multi-level tenant hierarchies and the runtime
``TenantPath`` that carries hierarchy context through tokens and requests.

Usage::

    hierarchy = TenantHierarchy(["organization", "region", "group"])

    path = TenantPath([
        TenantNode("acme", "organization"),
        TenantNode("us-west", "region"),
    ])
    path.leaf_id          # "us-west"
    path.id_at("organization")  # "acme"
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TenantLevel:
    """A named level in the tenant hierarchy (e.g., 'organization', 'region')."""

    name: str
    depth: int


@dataclass(frozen=True, slots=True)
class TenantNode:
    """A single segment in a tenant path: a concrete tenant at a specific level."""

    id: str
    level: str


@dataclass(frozen=True, slots=True)
class TenantPath:
    """Ordered path from root to leaf in the tenant hierarchy.

    Replaces the flat ``tenant_id`` string with full hierarchy context.
    The ``leaf_id`` property provides backward compatibility with code
    that expects a single tenant ID string.
    """

    nodes: tuple[TenantNode, ...]

    def __init__(self, nodes: Sequence[TenantNode] | tuple[TenantNode, ...]) -> None:
        object.__setattr__(self, "nodes", tuple(nodes))

    @property
    def leaf_id(self) -> str:
        """The most specific tenant ID (last node). Backward-compatible with flat tenant_id."""
        return self.nodes[-1].id

    @property
    def leaf_level(self) -> str:
        """The level name of the most specific tenant."""
        return self.nodes[-1].level

    def id_at(self, level: str) -> str | None:
        """Get the tenant ID at a specific hierarchy level, or ``None`` if absent."""
        for node in self.nodes:
            if node.level == level:
                return node.id
        return None

    def contains(self, other: TenantPath) -> bool:
        """Check if this path is an ancestor of (or equal to) *other*.

        True when every node in ``self`` appears at the same position in ``other``.
        """
        if len(self.nodes) > len(other.nodes):
            return False
        return all(s == o for s, o in zip(self.nodes, other.nodes, strict=False))

    def is_descendant_of(self, ancestor_id: str) -> bool:
        """Check if any segment in this path has the given tenant ID."""
        return any(node.id == ancestor_id for node in self.nodes)

    def to_claim(self) -> dict[str, str]:
        """Serialize for JWT embedding: ``{"organization": "acme", "region": "us-west"}``."""
        return {node.level: node.id for node in self.nodes}

    @classmethod
    def from_claim(cls, claim: dict[str, str]) -> TenantPath:
        """Deserialize from a JWT claim dict."""
        nodes = [TenantNode(id=tid, level=level) for level, tid in claim.items()]
        return cls(nodes)

    @classmethod
    def from_flat(cls, tenant_id: str, level: str = "tenant") -> TenantPath:
        """Wrap a flat tenant_id into a single-node path (backward compat)."""
        return cls((TenantNode(id=tenant_id, level=level),))

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self) -> Iterator[TenantNode]:
        return iter(self.nodes)

    def __repr__(self) -> str:
        parts = "/".join(f"{n.level}:{n.id}" for n in self.nodes)
        return f"TenantPath({parts})"


class TenantHierarchy:
    """Schema definition for the tenant hierarchy, configured at startup.

    Accepts either a list of level name strings (auto-numbered by depth)
    or explicit ``TenantLevel`` objects::

        TenantHierarchy(["organization", "region", "group"])
        TenantHierarchy([TenantLevel("organization", 0), TenantLevel("region", 1)])
    """

    def __init__(self, levels: Sequence[str | TenantLevel]) -> None:
        built: list[TenantLevel] = []
        for i, level in enumerate(levels):
            if isinstance(level, str):
                built.append(TenantLevel(name=level, depth=i))
            else:
                built.append(level)
        self._levels = tuple(built)
        self._by_name = {lvl.name: lvl for lvl in self._levels}

    def depth_of(self, level_name: str) -> int:
        """Return the depth of a level by name."""
        return self._by_name[level_name].depth

    def parent_of(self, level_name: str) -> str | None:
        """Return the parent level name, or ``None`` for the root level."""
        depth = self.depth_of(level_name)
        for lvl in self._levels:
            if lvl.depth == depth - 1:
                return lvl.name
        return None

    def children_of(self, level_name: str) -> list[str]:
        """Return immediate child level names."""
        depth = self.depth_of(level_name)
        return [lvl.name for lvl in self._levels if lvl.depth == depth + 1]

    def get(self, level_name: str) -> TenantLevel | None:
        """Get a level by name, or ``None``."""
        return self._by_name.get(level_name)

    @property
    def root(self) -> TenantLevel:
        """The root (top-most) level."""
        return self._levels[0]

    @property
    def leaf(self) -> TenantLevel:
        """The leaf (bottom-most) level."""
        return self._levels[-1]

    def __len__(self) -> int:
        return len(self._levels)

    def __iter__(self) -> Iterator[TenantLevel]:
        return iter(self._levels)

    def __getitem__(self, index: int) -> TenantLevel:
        return self._levels[index]

    def __contains__(self, level_name: str) -> bool:
        return level_name in self._by_name

    def __repr__(self) -> str:
        names = " → ".join(lvl.name for lvl in self._levels)
        return f"TenantHierarchy({names})"
