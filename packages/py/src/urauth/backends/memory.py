from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass
class _TokenRecord:
    jti: str
    user_id: str
    token_type: str
    expires_at: float
    family_id: str | None = None
    revoked: bool = False


class MemoryTokenStore:
    """In-memory token store for development and testing."""

    def __init__(self) -> None:
        self._tokens: dict[str, _TokenRecord] = {}
        self._user_tokens: dict[str, set[str]] = {}

    async def is_revoked(self, jti: str) -> bool:
        rec = self._tokens.get(jti)
        if rec is None:
            return False
        return rec.revoked

    async def revoke(self, jti: str, expires_at: float) -> None:
        rec = self._tokens.get(jti)
        if rec is not None:
            rec.revoked = True

    async def revoke_all_for_user(self, user_id: str) -> None:
        for jti in self._user_tokens.get(user_id, set()):
            rec = self._tokens.get(jti)
            if rec is not None:
                rec.revoked = True

    async def add_token(
        self, jti: str, user_id: str, token_type: str, expires_at: float, family_id: str | None = None
    ) -> None:
        rec = _TokenRecord(
            jti=jti,
            user_id=user_id,
            token_type=token_type,
            expires_at=expires_at,
            family_id=family_id,
        )
        self._tokens[jti] = rec
        self._user_tokens.setdefault(user_id, set()).add(jti)

    async def get_family_id(self, jti: str) -> str | None:
        rec = self._tokens.get(jti)
        return rec.family_id if rec else None

    async def revoke_family(self, family_id: str) -> None:
        for rec in self._tokens.values():
            if rec.family_id == family_id:
                rec.revoked = True


class MemorySessionStore:
    """In-memory session store for development and testing."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._user_sessions: dict[str, set[str]] = {}

    async def create(self, session_id: str, user_id: str, data: dict[str, Any], ttl: int) -> None:
        self._sessions[session_id] = {
            "user_id": user_id,
            "data": data,
            "expires_at": time.time() + ttl,
        }
        self._user_sessions.setdefault(user_id, set()).add(session_id)

    async def get(self, session_id: str) -> dict[str, Any] | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if time.time() > session["expires_at"]:
            del self._sessions[session_id]
            return None
        return session

    async def delete(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session:
            user_id = session["user_id"]
            self._user_sessions.get(user_id, set()).discard(session_id)

    async def delete_all_for_user(self, user_id: str) -> None:
        for sid in list(self._user_sessions.get(user_id, set())):
            self._sessions.pop(sid, None)
        self._user_sessions.pop(user_id, None)
