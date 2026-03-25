"""Typed permission primitives — Action, Resource, Permission, Relation, Role, RelationTuple.

Supports boolean composition::

    (member_of & editor) | admin
    can_read & can_write
    admin | (can_read & member_of)
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from urauth.context import AuthContext


# ── Separator auto-detection ──────────────────────────────────────

_SEP_RE = re.compile(r"[@#.:|\\/$&]")


# ── Shared permission matching ────────────────────────────────────


def match_permission(pattern: Permission | str, target: Permission | str) -> bool:
    """Check if a permission pattern matches a target permission.

    Performs semantic (resource, action) comparison — separator-agnostic.

    Supports:
    - Exact match: ``"user:read"`` matches ``"user.read"``
    - Global wildcard: ``"*"`` matches everything
    - Resource wildcard: ``"user:*"`` matches ``"user:read"``, ``"user.write"``, etc.
    """
    p = pattern if isinstance(pattern, Permission) else Permission(str(pattern))
    t = target if isinstance(target, Permission) else Permission(str(target))
    if str(p.resource) == "*":
        return True
    if str(p.resource) != str(t.resource):
        return False
    return str(p.action) == "*" or str(p.action) == str(t.action)


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

    Accepts two args, a single string (auto-detects separator), or a custom parser::

        Permission("user", "read")      # two-arg form
        Permission("user:read")         # colon separator (auto-detected)
        Permission("user.read")         # dot separator (auto-detected)
        Permission("user@read")         # any allowed separator
        Permission("*")                 # global wildcard

    Equality is semantic: ``Permission("user:read") == Permission("user.read")`` is ``True``.
    Supports ``&`` / ``|`` composition with other requirements.
    """

    __slots__ = ("_sep", "action", "resource")

    def __init__(
        self,
        resource: Resource | str,
        action: Action | str | None = None,
        *,
        separator: str = ":",
        parser: Callable[[str], tuple[str, str]] | None = None,
    ) -> None:
        if action is not None:
            self.resource = resource if isinstance(resource, Resource) else Resource(str(resource))
            self.action = action if isinstance(action, Action) else Action(str(action))
            self._sep = separator
        elif parser is not None:
            r, a = parser(str(resource))
            self.resource = Resource(r)
            self.action = Action(a)
            self._sep = separator
        else:
            value = str(resource)
            if value == "*":
                self.resource = Resource("*")
                self.action = Action("*")
                self._sep = separator
            else:
                m = _SEP_RE.search(value)
                if not m:
                    raise ValueError(
                        f"No separator found in permission string: {value!r}. "
                        f"Use one of: {' '.join(sorted(_SEP_RE.pattern[1:-1]))}"
                    )
                sep_char = m.group()
                parts = value.split(sep_char, 1)
                self.resource = Resource(parts[0])
                self.action = Action(parts[1])
                self._sep = sep_char

    def evaluate(self, ctx: AuthContext) -> bool:
        return ctx.has_permission(self)

    def __str__(self) -> str:
        return f"{self.resource}{self._sep}{self.action}"

    def __repr__(self) -> str:
        return f"Permission({self.resource!r}, {self.action!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Permission):
            return str(self.resource) == str(other.resource) and str(self.action) == str(other.action)
        if isinstance(other, str):
            try:
                p = Permission(other)
            except ValueError:
                return False
            return str(self.resource) == str(p.resource) and str(self.action) == str(p.action)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((str(self.resource), str(self.action)))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result  # type: ignore[return-value]
        return not result


class Relation(Requirement):
    """Zanzibar-style relation definition.

    Resource-first ordering matches the string form::

        Relation("doc", "owner")     # two-arg form
        Relation("doc#owner")        # string form (auto-detects separator)

    Equality is semantic: ``Relation("doc#owner") == Relation("doc.owner")`` is ``True``.
    Supports ``&`` / ``|`` composition with other requirements.
    """

    __slots__ = ("_sep", "name", "resource")

    def __init__(
        self,
        resource: Resource | str,
        name: str | None = None,
        *,
        separator: str = "#",
        parser: Callable[[str], tuple[str, str]] | None = None,
    ) -> None:
        if name is not None:
            self.resource = resource if isinstance(resource, Resource) else Resource(str(resource))
            self.name = str(name)
            self._sep = separator
        elif parser is not None:
            r, n = parser(str(resource))
            self.resource = Resource(r)
            self.name = n
            self._sep = separator
        else:
            value = str(resource)
            m = _SEP_RE.search(value)
            if not m:
                raise ValueError(
                    f"No separator found in relation string: {value!r}. "
                    f"Use one of: {' '.join(sorted(_SEP_RE.pattern[1:-1]))}"
                )
            sep_char = m.group()
            parts = value.split(sep_char, 1)
            self.resource = Resource(parts[0])
            self.name = parts[1]
            self._sep = sep_char

    @property
    def separator(self) -> str:
        """The separator character used for string representation."""
        return self._sep

    def tuple(self, object_id: str, subject: str | None = None) -> RelationTuple:
        """Create a full Zanzibar tuple from this relation definition."""
        return RelationTuple(relation=self, object_id=object_id, subject=subject)

    def evaluate(self, ctx: AuthContext) -> bool:
        return any(rt.relation == self for rt in ctx.relations)

    def __str__(self) -> str:
        return f"{self.resource}{self._sep}{self.name}"

    def __repr__(self) -> str:
        return f"Relation({self.resource!r}, {self.name!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Relation):
            return self.name == other.name and str(self.resource) == str(other.resource)
        if isinstance(other, str):
            try:
                r = Relation(other)
            except ValueError:
                return False
            return self.name == r.name and str(self.resource) == str(r.resource)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.name, str(self.resource)))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result  # type: ignore[return-value]
        return not result


class RelationTuple:
    """Full Zanzibar relationship tuple: ``object_type:object_id#relation@subject``.

    Construction::

        RelationTuple(Relation("doc", "owner"), "readme", "user:alice")
        RelationTuple.parse("doc:readme#owner@user:alice")

    The subject is an opaque string (or ``None`` if unknown).
    """

    __slots__ = ("object_id", "relation", "subject")

    def __init__(self, relation: Relation, object_id: str, subject: str | None = None) -> None:
        self.relation = relation
        self.object_id = object_id
        self.subject = subject

    @classmethod
    def parse(cls, s: str) -> RelationTuple:
        """Parse ``'doc:readme#owner@user:alice'`` positionally by separator and ``@``."""
        subject: str | None
        if "@" in s:
            left, subject = s.split("@", 1)
        else:
            left, subject = s, None
        # left = "doc:readme#owner"
        # Find first ":" for obj_type:obj_id split
        colon_pos = left.index(":")
        obj_type = left[:colon_pos]
        rest = left[colon_pos + 1:]  # "readme#owner"
        # Find relation separator in rest
        m = _SEP_RE.search(rest)
        if not m:
            raise ValueError(f"Invalid relation tuple: {s!r}")
        obj_id = rest[: m.start()]
        rel_name = rest[m.end() :]
        return cls(
            relation=Relation(obj_type, rel_name),
            object_id=obj_id,
            subject=subject,
        )

    def __str__(self) -> str:
        sep = self.relation.separator
        base = f"{self.relation.resource}:{self.object_id}{sep}{self.relation.name}"
        if self.subject is not None:
            return f"{base}@{self.subject}"
        return base

    def __repr__(self) -> str:
        return f"RelationTuple({self.relation!r}, {self.object_id!r}, {self.subject!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RelationTuple):
            return (
                self.relation == other.relation
                and self.object_id == other.object_id
                and self.subject == other.subject
            )
        if isinstance(other, str):
            return str(self) == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.relation, self.object_id, self.subject))

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
