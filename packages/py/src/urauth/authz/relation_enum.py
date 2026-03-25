"""RelationEnum — declarative Zanzibar relation definitions using enums."""

from __future__ import annotations

from enum import Enum
from typing import Any

from .primitives import Relation, RelationTuple


class RelationEnum(Enum):
    """Base class for declarative relation definitions.

    Each member's ``.value`` is a ``Relation`` instance (resource-first).
    Members delegate ``__str__``, ``__eq__``, ``__hash__`` to their value.

    Separator is auto-detected from the string form::

        class Rels(RelationEnum):
            DOC_OWNER = "doc#owner"                        # hash separator
            DOC_VIEWER = ("doc", "viewer")                 # tuple form
            FOLDER_EDITOR = Relation("folder", "editor")   # Relation object

    For edge cases, define ``__parser__`` to override auto-detection::

        class Rels(RelationEnum):
            __parser__ = my_custom_parser
            CUSTOM = "some:custom:format"
    """

    def __new__(cls, *args: Any) -> RelationEnum:
        parser = cls.__dict__.get("__parser__")

        if len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], str):
            # Tuple form: ("doc", "owner") → Relation("doc", "owner")
            rel = Relation(str(args[0]), str(args[1]))
        elif len(args) == 1 and isinstance(args[0], str):
            # String form: "doc#owner" → auto-detect separator
            rel = Relation(args[0], parser=parser)
        elif len(args) == 1 and isinstance(args[0], Relation):
            rel = args[0]
        else:
            raise TypeError(
                f"RelationEnum requires a string, (resource, name) tuple, or Relation, got {args!r}"
            )

        obj = object.__new__(cls)
        obj._value_ = rel
        return obj

    def tuple(self, object_id: str, subject: str | None = None) -> RelationTuple:
        """Create a full Zanzibar tuple from this relation definition."""
        return self.value.tuple(object_id, subject)

    def __str__(self) -> str:
        return str(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RelationEnum):
            return self.value == other.value
        if isinstance(other, (Relation, str)):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)
