"""PermissionEnum — declarative permission definitions using enums."""

from __future__ import annotations

from enum import Enum
from typing import Any

from .primitives import Permission


class PermissionEnum(Enum):
    """Base class for declarative permission definitions.

    Each member's ``.value`` is a ``Permission`` instance.
    Members delegate ``__str__``, ``__eq__``, ``__hash__`` to their value.

    Usage::

        class Perms(PermissionEnum):
            USER_READ = "user:read"                        # string form
            TASK_WRITE = ("task", "write")                  # tuple form
            ADMIN_ALL = Permission("admin", "*")            # Permission object
    """

    def __new__(cls, *args: Any) -> PermissionEnum:
        if len(args) == 2:
            # Tuple form: ("user", "read")
            perm = Permission(str(args[0]), str(args[1]))
        elif len(args) == 1 and isinstance(args[0], str):
            # String form: "user:read"
            perm = Permission(args[0])
        elif len(args) == 1 and isinstance(args[0], Permission):
            perm = args[0]
        else:
            raise TypeError(f"PermissionEnum requires a string, (resource, action) tuple, or Permission, got {args!r}")

        obj = object.__new__(cls)
        obj._value_ = perm
        return obj

    def __str__(self) -> str:
        return str(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PermissionEnum):
            return self.value == other.value
        if isinstance(other, (Permission, str)):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)
