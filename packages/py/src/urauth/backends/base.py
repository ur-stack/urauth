from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class UserBackend(Protocol):
    """Protocol that users must implement to provide user storage."""

    async def get_by_id(self, user_id: Any) -> Any | None:
        """Fetch a user by their unique ID."""
        ...

    async def get_by_username(self, username: str) -> Any | None:
        """Fetch a user by username/email (used for password login)."""
        ...

    async def verify_password(self, user: Any, password: str) -> bool:
        """Verify a plaintext password against the user's stored hash."""
        ...


@dataclass(frozen=True, slots=True)
class UserFunctions:
    """Internal container for user-related callables used by all internal code."""

    get_by_id: Callable[[Any], Awaitable[Any | None]]
    get_by_username: Callable[[str], Awaitable[Any | None]]
    verify_password: Callable[[Any, str], Awaitable[bool]]
    create_oauth_user: Callable[[Any], Awaitable[Any]] | None = None


def resolve_user_functions(
    auth_instance: Any,
    base_class: type,
    user_backend: UserBackend | None,
    get_user: Callable | None,
    get_user_by_username: Callable | None,
    verify_password: Callable | None,
    create_oauth_user: Callable | None = None,
) -> UserFunctions:
    """Resolve user functions from one of three sources.

    Resolution order:
    1. Subclass overrides on *auth_instance*
    2. Callables passed as keyword arguments
    3. A ``UserBackend`` protocol object

    Raises ``ValueError`` if no source is found or multiple conflict.
    """
    cls = type(auth_instance)

    # Detect subclass overrides
    has_overrides = (
        cls.get_user is not base_class.get_user
        or cls.get_user_by_username is not base_class.get_user_by_username
        or cls.verify_password is not base_class.verify_password
    )

    # Detect callables
    has_callables = any(fn is not None for fn in (get_user, get_user_by_username, verify_password))

    # Count sources
    sources = sum([has_overrides, has_callables, user_backend is not None])

    if sources == 0:
        raise ValueError(
            "No user functions provided. Either subclass FastAPIAuth and override "
            "get_user/get_user_by_username/verify_password, pass them as callables, "
            "or provide a UserBackend instance."
        )

    if sources > 1:
        raise ValueError(
            "Multiple user function sources detected. Use only one of: "
            "subclass overrides, callables, or a UserBackend instance."
        )

    if has_overrides:
        oauth_create = None
        if cls.create_oauth_user is not base_class.create_oauth_user:
            oauth_create = auth_instance.create_oauth_user
        return UserFunctions(
            get_by_id=auth_instance.get_user,
            get_by_username=auth_instance.get_user_by_username,
            verify_password=auth_instance.verify_password,
            create_oauth_user=oauth_create,
        )

    if has_callables:
        if get_user is None or get_user_by_username is None or verify_password is None:
            raise ValueError(
                "When using callables, all three are required: "
                "get_user, get_user_by_username, and verify_password."
            )
        return UserFunctions(
            get_by_id=get_user,
            get_by_username=get_user_by_username,
            verify_password=verify_password,
            create_oauth_user=create_oauth_user,
        )

    # user_backend
    assert user_backend is not None
    oauth_create = getattr(user_backend, "create_oauth_user", None)
    return UserFunctions(
        get_by_id=user_backend.get_by_id,
        get_by_username=user_backend.get_by_username,
        verify_password=user_backend.verify_password,
        create_oauth_user=oauth_create,
    )


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
        self, jti: str, user_id: str, token_type: str, expires_at: float, family_id: str | None = None
    ) -> None:
        """Track an issued token (for refresh-family reuse detection)."""
        ...

    async def get_family_id(self, jti: str) -> str | None:
        """Return the family ID for a refresh token, or None."""
        ...

    async def revoke_family(self, family_id: str) -> None:
        """Revoke all tokens in a refresh-token family (reuse detection)."""
        ...


@runtime_checkable
class SessionStore(Protocol):
    """Protocol for server-side session storage."""

    async def create(self, session_id: str, user_id: str, data: dict[str, Any], ttl: int) -> None: ...
    async def get(self, session_id: str) -> dict[str, Any] | None: ...
    async def delete(self, session_id: str) -> None: ...
    async def delete_all_for_user(self, user_id: str) -> None: ...
