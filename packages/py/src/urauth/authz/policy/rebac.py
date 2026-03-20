"""Relationship-Based Access Control policy."""

from __future__ import annotations

from ..context import AccessContext
from ..exceptions import ConfigurationError
from .base import Policy


class ReBACPolicy(Policy):
    """Relationship-Based Access Control.

    Checks subject's relationships against required relations for resources.
    Resource format convention: "type:id" (e.g. "document:123").

    Usage:
        rebac = ReBACPolicy()
        rebac.allow_if("owner", resource_type="document")
        rebac.allow_if("viewer")
        rebac.imply("owner", "editor").imply("editor", "viewer")
    """

    def __init__(self) -> None:
        self._required_relations: list[tuple[str, str | None]] = []
        self._implications: dict[str, set[str]] = {}  # relation -> implied relations
        self._resolved_cache: dict[str, set[str]] = {}

    def allow_if(
        self, relation: str, *, resource_type: str | None = None
    ) -> ReBACPolicy:
        """Allow access if subject has the given relation to the resource.

        Args:
            relation: The relationship name (e.g. "owner", "editor", "viewer")
            resource_type: Optional resource type filter (e.g. "document")
        """
        self._required_relations.append((relation, resource_type))
        return self

    def imply(self, source: str, target: str) -> ReBACPolicy:
        """Declare that having `source` relation implies `target` relation.

        E.g. imply("owner", "editor") means owners are also editors.
        """
        if source == target:
            raise ConfigurationError(
                f"Relation '{source}' cannot imply itself"
            )
        if source not in self._implications:
            self._implications[source] = set()
        self._implications[source].add(target)
        self._resolved_cache.clear()
        self._detect_cycle(source, set())
        return self

    def _detect_cycle(self, relation: str, visited: set[str]) -> None:
        if relation in visited:
            raise ConfigurationError(
                f"Cycle detected in relation implications involving '{relation}'"
            )
        visited.add(relation)
        for implied in self._implications.get(relation, ()):
            self._detect_cycle(implied, visited.copy())

    def _resolve_implications(self, relation: str) -> set[str]:
        """Get all relations implied by a given relation (including itself)."""
        if relation in self._resolved_cache:
            return self._resolved_cache[relation]

        result: set[str] = {relation}
        for implied in self._implications.get(relation, ()):
            result |= self._resolve_implications(implied)

        self._resolved_cache[relation] = result
        return result

    def _get_all_relations(self, subject_relationships: dict[str, set[str]]) -> dict[str, set[str]]:
        """Expand subject relationships with implications."""
        expanded: dict[str, set[str]] = {}
        for relation, resources in subject_relationships.items():
            for resolved in self._resolve_implications(relation):
                if resolved not in expanded:
                    expanded[resolved] = set()
                expanded[resolved] |= resources
        return expanded

    async def evaluate(self, context: AccessContext) -> bool:
        """Check if subject has any required relation to the resource."""
        if not self._required_relations:
            return True

        resource = context.resource
        if resource is None:
            return False

        expanded = self._get_all_relations(
            dict(context.subject.relationships)
        )

        resource_type = resource.split(":")[0] if ":" in resource else None

        for required_relation, req_resource_type in self._required_relations:
            # Filter by resource type if specified
            if req_resource_type is not None and resource_type != req_resource_type:
                continue

            # Check if subject has this relation to the resource
            related_resources = expanded.get(required_relation, set())
            if resource in related_resources:
                return True

        return False

    def description(self) -> str | None:
        relations = [r for r, _ in self._required_relations]
        return f"ReBAC policy (relations: {', '.join(relations) or 'none'})"
