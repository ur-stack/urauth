"""TypeVars and type aliases for generic access control."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

RoleT = TypeVar("RoleT", bound=str)
PermissionT = TypeVar("PermissionT", bound=str)
ResourceT = TypeVar("ResourceT", bound=str)

SubjectResolver = Callable[[Any], Any] | Callable[[Any], Awaitable[Any]]
