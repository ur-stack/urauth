"""Access context passed to policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .subject import Subject


@dataclass
class AccessContext:
    """Context object passed to policies for evaluation."""

    subject: Subject
    action: str | None = None
    resource: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)
