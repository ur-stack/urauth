"""Base policy protocol and abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..context import AccessContext


class Policy(ABC):
    """Abstract base for all access control policies."""

    @abstractmethod
    async def evaluate(self, context: AccessContext) -> bool:
        """Evaluate whether the given context should be allowed.

        Returns True if access is granted, False if denied.
        """
        ...

    async def __call__(self, context: AccessContext) -> bool:
        return await self.evaluate(context)

    def description(self) -> str | None:
        """Optional human-readable description of this policy."""
        return None
