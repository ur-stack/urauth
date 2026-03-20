"""Attribute-Based Access Control policy."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..context import AccessContext
from ..exceptions import PolicyEvaluationError
from .base import Policy


class Operator(str, Enum):
    """Comparison operators for ABAC rules."""
    EQ = "eq"
    NEQ = "neq"
    IN = "in_"
    CONTAINS = "contains"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    MATCHES = "matches"


@dataclass
class ABACRule:
    """A single attribute-based rule."""
    attribute: str
    operator: Operator
    value: Any
    target: str = "subject"  # "subject" or "resource"


def _resolve_dotpath(obj: Any, path: str) -> Any:
    """Resolve a dot-notation path against an object.

    Supports paths like "subject.attributes.department".
    """
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                raise KeyError(f"Key '{part}' not found in path '{path}'")
            current = current[part]
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            raise AttributeError(
                f"Cannot resolve '{part}' in path '{path}'"
            )
    return current


def _evaluate_operator(actual: Any, operator: Operator, expected: Any) -> bool:
    """Evaluate a single operator comparison."""
    if operator == Operator.EQ:
        return actual == expected
    elif operator == Operator.NEQ:
        return actual != expected
    elif operator == Operator.IN:
        return actual in expected
    elif operator == Operator.CONTAINS:
        return expected in actual
    elif operator == Operator.GT:
        return actual > expected
    elif operator == Operator.LT:
        return actual < expected
    elif operator == Operator.GTE:
        return actual >= expected
    elif operator == Operator.LTE:
        return actual <= expected
    elif operator == Operator.MATCHES:
        return bool(re.search(expected, str(actual)))
    return False


class _RuleBuilder:
    """Fluent builder for ABAC rules."""

    def __init__(self, policy: ABACPolicy, attribute: str) -> None:
        self._policy = policy
        self._attribute = attribute

    def equals(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.EQ, value))
        return self._policy

    def not_equals(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.NEQ, value))
        return self._policy

    def in_(self, value: Sequence[Any]) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.IN, value))
        return self._policy

    def contains(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.CONTAINS, value))
        return self._policy

    def greater_than(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.GT, value))
        return self._policy

    def less_than(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.LT, value))
        return self._policy

    def gte(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.GTE, value))
        return self._policy

    def lte(self, value: Any) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.LTE, value))
        return self._policy

    def matches(self, pattern: str) -> ABACPolicy:
        self._policy.add_rule(ABACRule(self._attribute, Operator.MATCHES, pattern))
        return self._policy


class ABACPolicy(Policy):
    """Attribute-Based Access Control.

    Usage:
        abac = ABACPolicy()
        abac.when("subject.attributes.department").equals("engineering")
        abac.add_rule(ABACRule("subject.attributes.level", Operator.GTE, 5))
    """

    def __init__(self, *, match_any: bool = False) -> None:
        self._rules: list[ABACRule] = []
        self._match_any = match_any

    def add_rule(self, rule: ABACRule) -> ABACPolicy:
        """Add a rule directly. Returns self for chaining."""
        self._rules.append(rule)
        return self

    def when(self, attribute: str) -> _RuleBuilder:
        """Start a fluent rule builder for the given attribute path."""
        return _RuleBuilder(self, attribute)

    async def evaluate(self, context: AccessContext) -> bool:
        """Evaluate all rules against the context."""
        if not self._rules:
            return True

        context_dict: dict[str, Any] = {
            "subject": context.subject,
            "resource": context.resource,
            "action": context.action,
            "extras": context.extras,
        }

        results: list[bool] = []
        for rule in self._rules:
            try:
                actual = _resolve_dotpath(context_dict, rule.attribute)
                result = _evaluate_operator(actual, rule.operator, rule.value)
                results.append(result)
            except (KeyError, AttributeError, TypeError) as e:
                raise PolicyEvaluationError(
                    f"Failed to evaluate ABAC rule on '{rule.attribute}': {e}"
                ) from e

        if self._match_any:
            return any(results)
        return all(results)

    def description(self) -> str | None:
        mode = "ANY" if self._match_any else "ALL"
        return f"ABAC policy ({len(self._rules)} rules, mode={mode})"
