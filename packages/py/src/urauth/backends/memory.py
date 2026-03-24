from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _TokenRecord:
    jti: str
    user_id: str
    token_type: str
    expires_at: float
    created_at: float = 0.0
    family_id: str | None = None
    revoked: bool = False


@dataclass
class _FamilyRecord:
    family_id: str
    user_id: str
    created_at: float
    metadata: dict[str, Any] = field(default_factory=dict)


class MemoryTokenStore:
    """In-memory token store for development and testing."""

    def __init__(self) -> None:
        self._tokens: dict[str, _TokenRecord] = {}
        self._user_tokens: dict[str, set[str]] = {}
        self._families: dict[str, _FamilyRecord] = {}
        self._user_families: dict[str, set[str]] = {}

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
        self,
        jti: str,
        user_id: str,
        token_type: str,
        expires_at: float,
        family_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        now = time.time()
        rec = _TokenRecord(
            jti=jti,
            user_id=user_id,
            token_type=token_type,
            expires_at=expires_at,
            created_at=now,
            family_id=family_id,
        )
        self._tokens[jti] = rec
        self._user_tokens.setdefault(user_id, set()).add(jti)

        # Track family (session) — create on first token, update metadata if provided
        if family_id is not None:
            if family_id not in self._families:
                self._families[family_id] = _FamilyRecord(
                    family_id=family_id,
                    user_id=user_id,
                    created_at=now,
                    metadata=metadata or {},
                )
                self._user_families.setdefault(user_id, set()).add(family_id)
            elif metadata:
                self._families[family_id].metadata.update(metadata)

    async def get_family_id(self, jti: str) -> str | None:
        rec = self._tokens.get(jti)
        return rec.family_id if rec else None

    async def revoke_family(self, family_id: str) -> None:
        for rec in self._tokens.values():
            if rec.family_id == family_id:
                rec.revoked = True

    async def get_sessions(self, user_id: str) -> list[dict[str, Any]]:
        now = time.time()
        result: list[dict[str, Any]] = []
        for family_id in self._user_families.get(user_id, set()):
            fam = self._families.get(family_id)
            if fam is None:
                continue

            # A session is active if it has any non-revoked, non-expired token
            has_active = False
            max_expires = 0.0
            for rec in self._tokens.values():
                if rec.family_id == family_id and not rec.revoked and rec.expires_at > now:
                    has_active = True
                    max_expires = max(max_expires, rec.expires_at)

            if has_active:
                result.append(
                    {
                        "family_id": family_id,
                        "created_at": fam.created_at,
                        "expires_at": max_expires,
                        "metadata": fam.metadata,
                    }
                )
        return result


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
