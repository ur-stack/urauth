"""Policy combinators for composing multiple policies."""

from __future__ import annotations

from ..context import AccessContext
from .base import Policy


class AllOf(Policy):
    """AND combinator — all policies must allow. Short-circuits on first False."""

    def __init__(self, *policies: Policy) -> None:
        self._policies = policies

    async def evaluate(self, context: AccessContext) -> bool:
        for policy in self._policies:
            if not await policy.evaluate(context):
                return False
        return True

    def description(self) -> str | None:
        names = [type(p).__name__ for p in self._policies]
        return f"AllOf({', '.join(names)})"


class AnyOf(Policy):
    """OR combinator — any policy must allow. Short-circuits on first True."""

    def __init__(self, *policies: Policy) -> None:
        self._policies = policies

    async def evaluate(self, context: AccessContext) -> bool:
        for policy in self._policies:
            if await policy.evaluate(context):
                return True
        return False

    def description(self) -> str | None:
        names = [type(p).__name__ for p in self._policies]
        return f"AnyOf({', '.join(names)})"


class NotPolicy(Policy):
    """Inverts the result of another policy."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    async def evaluate(self, context: AccessContext) -> bool:
        return not await self._policy.evaluate(context)

    def description(self) -> str | None:
        return f"Not({type(self._policy).__name__})"
