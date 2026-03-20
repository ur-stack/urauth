"""Session-based auth dependency."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request

from urauth.backends.base import UserFunctions
from urauth.exceptions import UnauthorizedError
from urauth.fastapi.sessions import SessionManager


def session_dependency(
    session_manager: SessionManager,
    user_fns: UserFunctions,
) -> Callable:
    """Return a FastAPI dependency that resolves the user from a session cookie."""

    async def _get_session_user(request: Request) -> Any:
        session = await session_manager.get_session(request)
        if session is None:
            raise UnauthorizedError("No valid session")

        user_id = session.get("user_id")
        if user_id is None:
            raise UnauthorizedError("Invalid session")

        user = await user_fns.get_by_id(user_id)
        if user is None:
            raise UnauthorizedError("User not found")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        return user

    return _get_session_user
