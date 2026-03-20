"""Subject model representing the authenticated entity."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Subject:
    """Represents an authenticated user/entity for access control evaluation.

    Users build a Subject in their resolver from JWT claims, DB lookups, etc.
    """

    id: str
    roles: Sequence[str] = ()
    permissions: Sequence[str] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: dict[str, set[str]] = field(default_factory=dict)
