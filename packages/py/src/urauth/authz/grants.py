"""PermissionSet helper for loading permissions from various sources."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Sequence
from enum import Enum
from typing import Any


class PermissionSet:
    """A set of permission strings with factory methods for various sources."""

    def __init__(self, permissions: set[str]) -> None:
        self._permissions = set(permissions)

    @classmethod
    def from_enum(cls, enum_class: type[Enum]) -> PermissionSet:
        """Create from an Enum class whose values are permission strings."""
        return cls({str(member.value) for member in enum_class})

    @classmethod
    def from_list(cls, permissions: Sequence[str]) -> PermissionSet:
        """Create from a list of strings."""
        return cls(set(permissions))

    @classmethod
    def from_env(cls, var_name: str, *, separator: str = ",") -> PermissionSet:
        """Create from a comma-separated (or custom separator) environment variable."""
        raw = os.environ.get(var_name, "")
        if not raw:
            return cls(set())
        return cls({p.strip() for p in raw.split(separator) if p.strip()})

    @classmethod
    async def from_db(
        cls,
        loader: Callable[[], Sequence[str]] | Callable[[], Awaitable[Sequence[str]]],
    ) -> PermissionSet:
        """Create from an async or sync loader function (e.g. database query)."""
        import inspect

        result = loader()
        if inspect.isawaitable(result):
            result = await result
        return cls(set(result))  # type: ignore[arg-type]

    def __contains__(self, item: Any) -> bool:
        return str(item) in self._permissions

    def __iter__(self):  # type: ignore[override]
        return iter(self._permissions)

    def __len__(self) -> int:
        return len(self._permissions)

    def __repr__(self) -> str:
        return f"PermissionSet({self._permissions!r})"

    def to_set(self) -> set[str]:
        return set(self._permissions)
