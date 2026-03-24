"""Typed permission primitives — Action, Resource, Permission, Relation, Role.

Supports boolean composition::

    (member_of & editor) | admin
    can_read & can_write
    admin | (can_read & member_of)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from urauth.context import AuthContext


# ── Shared permission matching ────────────────────────────────────


def match_permission(pattern: str, target: str, *, separator: str = ":") -> bool:
    """Check if a permission pattern matches a target permission string.

    Supports:
    - Exact match: ``"user:read"`` matches ``"user:read"``
    - Global wildcard: ``"*"`` matches everything
    - Resource wildcard: ``"user:*"`` matches ``"user:read"``, ``"user:write"``, etc.
    """
    if pattern == "*":
        return True
    if pattern == target:
        return True
    # Resource wildcard: "user:*" matches "user:read"
    suffix = f"{separator}*"
    if pattern.endswith(suffix):
        prefix = pattern[: -len(suffix)]
        target_resource = target.split(separator, 1)[0] if separator in target else target
        return prefix == target_resource
    return False


# ── Composite requirements ──────────────────────────────────────


class Requirement:
    """Base for composable requirements. Supports ``&`` (AND) and ``|`` (OR).

    All primitive types (Permission, Role, Relation) inherit these operators.
    """

    def __and__(self, other: Requirement) -> AllOf:
        left = list(self.all_of_items()) if isinstance(self, AllOf) else [self]
        right = list(other.all_of_items()) if isinstance(other, AllOf) else [other]
        return AllOf(left + right)

    def __or__(self, other: Requirement) -> AnyOf:
        left = list(self.any_of_items()) if isinstance(self, AnyOf) else [self]
        right = list(other.any_of_items()) if isinstance(other, AnyOf) else [other]
        return AnyOf(left + right)

    def all_of_items(self) -> list[Requirement]:
        return [self]

    def any_of_items(self) -> list[Requirement]:
        return [self]

    def evaluate(self, ctx: AuthContext) -> bool:
        """Evaluate this requirement against an AuthContext. Override in subclasses."""
        raise NotImplementedError


class AllOf(Requirement):
    """Composite: all requirements must be satisfied (AND)."""

    __slots__ = ("requirements",)

    def __init__(self, requirements: list[Requirement]) -> None:
        self.requirements = requirements

    def all_of_items(self) -> list[Requirement]:
        return list(self.requirements)

    def evaluate(self, ctx: AuthContext) -> bool:
        return all(r.evaluate(ctx) for r in self.requirements)

    def __repr__(self) -> str:
        return f"AllOf({self.requirements!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AllOf):
            return self.requirements == other.requirements
        return NotImplemented

    def __hash__(self) -> int:
        return hash(tuple(self.requirements))


class AnyOf(Requirement):
    """Composite: any requirement must be satisfied (OR)."""

    __slots__ = ("requirements",)

    def __init__(self, requirements: list[Requirement]) -> None:
        self.requirements = requirements

    def any_of_items(self) -> list[Requirement]:
        return list(self.requirements)

    def evaluate(self, ctx: AuthContext) -> bool:
        return any(r.evaluate(ctx) for r in self.requirements)

    def __repr__(self) -> str:
        return f"AnyOf({self.requirements!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AnyOf):
            return self.requirements == other.requirements
        return NotImplemented

    def __hash__(self) -> int:
        return hash(tuple(self.requirements))


# ── Primitives ──────────────────────────────────────────────────


class Action(str):
    """A typed action identifier. Subclasses ``str`` so it dissolves at boundaries."""

    __slots__ = ()


class Resource(str):
    """A typed resource identifier. Subclasses ``str`` so it dissolves at boundaries."""

    __slots__ = ()


class Permission(Requirement):
    """A typed permission combining a resource and an action.

    Accepts either two args or a single string::

        Permission("user", "read")   # two-arg form
        Permission("user:read")      # single-string form (splits on separator)

    Compares equal to its string form: ``Permission("user:read") == "user:read"``.
    Supports ``&`` / ``|`` composition with other requirements.
    """

    __slots__ = ("action", "resource")

    def __init__(
        self,
        resource: Resource | str,
        action: Action | str | None = None,
        *,
        separator: str = ":",
    ) -> None:
        if action is not None:
            # Two-arg form: Permission("user", "read")
            self.resource = resource if isinstance(resource, Resource) else Resource(str(resource))
            self.action = action if isinstance(action, Action) else Action(str(action))
        else:
            # Single-string form: Permission("user:read")
            value = str(resource)
            parts = value.split(separator, 1)
            if len(parts) != 2:
                raise ValueError(f"Permission string must contain '{separator}': got {value!r}")
            self.resource = Resource(parts[0])
            self.action = Action(parts[1])

    def evaluate(self, ctx: AuthContext) -> bool:
        return ctx.has_permission(self)

    def __str__(self) -> str:
        return f"{self.resource}:{self.action}"

    def __repr__(self) -> str:
        return f"Permission({self.resource!r}, {self.action!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Permission):
            return str(self) == str(other)
        if isinstance(other, str):
            return str(self) == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(str(self))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result  # type: ignore[return-value]
        return not result


class Relation(Requirement):
    """Zanzibar-style relation definition.

    Compares equal to its string form: ``Relation("owner", "post") == "post#owner"``.
    Supports ``&`` / ``|`` composition with other requirements.

    When used in a composite requirement (via ``evaluate``), checks if the
    relation exists for ANY resource ID in the context.
    """

    __slots__ = ("name", "resource")

    def __init__(self, name: str, resource: Resource | str) -> None:
        self.name = name
        self.resource = resource if isinstance(resource, Resource) else Resource(resource)

    def evaluate(self, ctx: AuthContext) -> bool:
        return any(r == self for r, _ in ctx.relations)

    def __str__(self) -> str:
        return f"{self.resource}#{self.name}"

    def __repr__(self) -> str:
        return f"Relation({self.name!r}, {self.resource!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Relation):
            return self.name == other.name and str(self.resource) == str(other.resource)
        if isinstance(other, str):
            return str(self) == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.name, str(self.resource)))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result  # type: ignore[return-value]
        return not result


class Role(Requirement):
    """Static role definition with associated permissions.

    Compares equal to its name string: ``Role("admin", [...]) == "admin"``.
    Supports ``&`` / ``|`` composition with other requirements.
    """

    __slots__ = ("name", "permissions")

    def __init__(self, name: str, permissions: list[Permission] | None = None) -> None:
        self.name = name
        self.permissions = list(permissions) if permissions else []

    def evaluate(self, ctx: AuthContext) -> bool:
        return ctx.has_role(self)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"Role({self.name!r}, {self.permissions!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Role):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.name)

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result  # type: ignore[return-value]
        return not result
