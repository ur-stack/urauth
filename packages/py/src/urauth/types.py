from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class UserProtocol(Protocol):
    """Minimal user protocol. Any object with these attributes works."""

    @property
    def id(self) -> Any: ...

    @property
    def is_active(self) -> bool: ...


@runtime_checkable
class UserWithRoles(UserProtocol, Protocol):
    """User that carries role information."""

    @property
    def roles(self) -> list[str]: ...


@runtime_checkable
class TenantUser(UserWithRoles, Protocol):
    """User scoped to a tenant."""

    @property
    def tenant_id(self) -> str: ...


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Decoded JWT claims."""

    sub: str
    jti: str
    iat: float
    exp: float
    token_type: str = "access"
    scopes: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    tenant_id: str | None = None
    tenant_path: dict[str, str] | None = None
    fresh: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class HierarchicalTenantUser(TenantUser, Protocol):
    """User scoped to a hierarchical tenant with full path context."""

    @property
    def tenant_path(self) -> dict[str, str]: ...


@dataclass(frozen=True, slots=True)
class TokenPair:
    """Access + refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
