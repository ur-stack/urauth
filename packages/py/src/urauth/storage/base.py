from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class UserFunctions:
    """Internal container for user-related callables used by all internal code."""

    get_by_id: Callable[[Any], Awaitable[Any | None]]
    get_by_username: Callable[[str], Awaitable[Any | None]]
    verify_password: Callable[[Any, str], Awaitable[bool]]


@runtime_checkable
class TokenStore(Protocol):
    """Protocol for token revocation storage."""

    async def is_revoked(self, jti: str) -> bool:
        """Check if a token (by JTI) has been revoked."""
        ...

    async def revoke(self, jti: str, expires_at: float) -> None:
        """Revoke a token. *expires_at* allows stores to auto-expire entries."""
        ...

    async def revoke_all_for_user(self, user_id: str) -> None:
        """Revoke all tokens belonging to a user (e.g. on password change)."""
        ...

    async def add_token(
        self,
        jti: str,
        user_id: str,
        token_type: str,
        expires_at: float,
        family_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Track an issued token (for refresh-family reuse detection).

        *metadata* is stored per family (session) and typically set on login.
        """
        ...

    async def get_family_id(self, jti: str) -> str | None:
        """Return the family ID for a refresh token, or None."""
        ...

    async def revoke_family(self, family_id: str) -> None:
        """Revoke all tokens in a refresh-token family (reuse detection)."""
        ...

    async def get_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """Return active sessions for a user, grouped by family.

        Each dict contains: ``family_id``, ``created_at``, ``expires_at``, ``metadata``.
        A session is a family of access + refresh tokens created at login.
        """
        ...


@runtime_checkable
class SessionStore(Protocol):
    """Protocol for server-side session storage."""

    async def create(self, session_id: str, user_id: str, data: dict[str, Any], ttl: int) -> None: ...
    async def get(self, session_id: str) -> dict[str, Any] | None: ...
    async def delete(self, session_id: str) -> None: ...
    async def delete_all_for_user(self, user_id: str) -> None: ...
