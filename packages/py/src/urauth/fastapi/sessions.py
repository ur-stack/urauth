"""Session manager coordinating session lifecycle."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import Request, Response

from urauth.backends.base import SessionStore
from urauth.config import AuthConfig


class SessionManager:
    """Create, retrieve, and destroy server-side sessions."""

    def __init__(self, store: SessionStore, config: AuthConfig) -> None:
        self._store = store
        self._config = config

    async def create_session(
        self,
        user_id: str,
        response: Response,
        data: dict[str, Any] | None = None,
    ) -> str:
        session_id = secrets.token_urlsafe(32)
        await self._store.create(
            session_id=session_id,
            user_id=user_id,
            data=data or {},
            ttl=self._config.session_ttl,
        )
        response.set_cookie(
            key=self._config.session_cookie_name,
            value=session_id,
            max_age=self._config.session_ttl,
            httponly=self._config.session_cookie_httponly,
            secure=self._config.session_cookie_secure,
            samesite=self._config.session_cookie_samesite,
        )
        return session_id

    async def get_session(self, request: Request) -> dict[str, Any] | None:
        session_id = request.cookies.get(self._config.session_cookie_name)
        if not session_id:
            return None
        return await self._store.get(session_id)

    async def destroy_session(self, request: Request, response: Response) -> None:
        session_id = request.cookies.get(self._config.session_cookie_name)
        if session_id:
            await self._store.delete(session_id)
        response.delete_cookie(key=self._config.session_cookie_name)

    async def destroy_all_for_user(self, user_id: str) -> None:
        await self._store.delete_all_for_user(user_id)
