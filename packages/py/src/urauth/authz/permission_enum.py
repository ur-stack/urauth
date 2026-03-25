"""PermissionEnum — declarative permission definitions using enums."""

from __future__ import annotations

from enum import Enum
from typing import Any

from .primitives import Permission


class PermissionEnum(Enum):
    """Base class for declarative permission definitions.

    Each member's ``.value`` is a ``Permission`` instance.
    Members delegate ``__str__``, ``__eq__``, ``__hash__`` to their value.

    Separator is auto-detected from the string form. Any allowed separator works::

        class Perms(PermissionEnum):
            USER_READ = "user:read"                        # colon
            TASK_WRITE = "task.write"                      # dot
            ADMIN_ALL = ("admin", "*")                     # tuple form
            CUSTOM = Permission("x", "y")                  # Permission object

    For edge cases, define ``__parser__`` to override auto-detection::

        class Perms(PermissionEnum):
            __parser__ = lambda s: (s.split(":")[-2], s.split(":")[-1])
            TASK_READ = "urn:service:task:read"
    """

    def __new__(cls, *args: Any) -> PermissionEnum:
        parser = cls.__dict__.get("__parser__")

        if len(args) == 2:
            perm = Permission(str(args[0]), str(args[1]))
        elif len(args) == 1 and isinstance(args[0], str):
            perm = Permission(args[0], parser=parser)
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
