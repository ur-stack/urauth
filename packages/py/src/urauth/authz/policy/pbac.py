"""Policy-Based Access Control (IAM-style statements)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Any

from ..context import AccessContext
from ..exceptions import PolicyEvaluationError
from .abac import Operator, _evaluate_operator, _resolve_dotpath
from .base import Policy


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Condition:
    """A condition on a policy statement."""
    attribute: str
    operator: Operator
    value: Any


@dataclass
class PolicyStatement:
    """An IAM-style policy statement."""
    effect: Effect
    actions: Sequence[str]
    resources: Sequence[str] = ("*",)
    conditions: Sequence[Condition] = field(default_factory=list)


class PBACPolicy(Policy):
    """Policy-Based Access Control with deny-first evaluation.

    Usage:
        pbac = PBACPolicy()
        pbac.add_statement(PolicyStatement(
            effect=Effect.ALLOW,
            actions=["read", "write"],
            resources=["document:*"],
        ))
        pbac.add_statement(PolicyStatement(
            effect=Effect.DENY,
            actions=["delete"],
            resources=["*"],
        ))
    """

    def __init__(self) -> None:
        self._statements: list[PolicyStatement] = []

    def add_statement(self, statement: PolicyStatement) -> PBACPolicy:
        """Add a policy statement. Returns self for chaining."""
        self._statements.append(statement)
        return self

    def allow(
        self,
        actions: Sequence[str],
        resources: Sequence[str] = ("*",),
        conditions: Sequence[Condition] = (),
    ) -> PBACPolicy:
        """Shorthand to add an ALLOW statement."""
        return self.add_statement(
            PolicyStatement(Effect.ALLOW, actions, resources, list(conditions))
        )

    def deny(
        self,
        actions: Sequence[str],
        resources: Sequence[str] = ("*",),
        conditions: Sequence[Condition] = (),
    ) -> PBACPolicy:
        """Shorthand to add a DENY statement."""
        return self.add_statement(
            PolicyStatement(Effect.DENY, actions, resources, list(conditions))
        )

    def _action_matches(self, pattern: str, action: str) -> bool:
        return fnmatch(action, pattern)

    def _resource_matches(self, pattern: str, resource: str) -> bool:
        return fnmatch(resource, pattern)

    def _evaluate_conditions(
        self, conditions: Sequence[Condition], context: AccessContext
    ) -> bool:
        """Check all conditions on a statement."""
        context_dict: dict[str, Any] = {
            "subject": context.subject,
            "resource": context.resource,
            "action": context.action,
            "extras": context.extras,
        }
        for condition in conditions:
            try:
                actual = _resolve_dotpath(context_dict, condition.attribute)
                if not _evaluate_operator(actual, condition.operator, condition.value):
                    return False
            except (KeyError, AttributeError, TypeError) as e:
                raise PolicyEvaluationError(
                    f"Failed to evaluate condition on '{condition.attribute}': {e}"
                ) from e
        return True

    async def evaluate(self, context: AccessContext) -> bool:
        """Deny-first evaluation: explicit deny always wins."""
        action = context.action or ""
        resource = context.resource or "*"

        has_allow = False

        for stmt in self._statements:
            action_match = any(
                self._action_matches(p, action) for p in stmt.actions
            )
            resource_match = any(
                self._resource_matches(p, resource) for p in stmt.resources
            )

            if not (action_match and resource_match):
                continue

            if not self._evaluate_conditions(stmt.conditions, context):
                continue

            if stmt.effect == Effect.DENY:
                return False

            if stmt.effect == Effect.ALLOW:
                has_allow = True

        return has_allow

    def description(self) -> str | None:
        allows = sum(1 for s in self._statements if s.effect == Effect.ALLOW)
        denies = sum(1 for s in self._statements if s.effect == Effect.DENY)
        return f"PBAC policy ({allows} allow, {denies} deny statements)"
