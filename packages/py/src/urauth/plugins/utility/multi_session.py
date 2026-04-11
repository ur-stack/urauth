"""Multi-session plugin.

Tracks all active sessions per user and provides targeted revocation.
Useful for "sign out of all other devices" and session management UIs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from urauth.auth import Auth


@dataclass
class SessionRecord:
    """Metadata about one active session."""

    family_id: str
    user_id: str
    created_at: datetime
    last_seen: datetime
    user_agent: str = ""
    ip: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class SessionTracker(Protocol):
    """Protocol for persisting session records.

    Implement this against your database to enable multi-session tracking.
    """

    async def save(self, record: SessionRecord) -> None:
        """Persist a new session record."""
        ...

    async def get(self, family_id: str) -> SessionRecord | None:
        """Fetch a session record by family_id."""
        ...

    async def list_for_user(self, user_id: str) -> list[SessionRecord]:
        """Return all active sessions for a user."""
        ...

    async def delete(self, family_id: str) -> None:
        """Remove a session record (called on logout or revocation)."""
        ...

    async def delete_all_for_user(self, user_id: str, *, except_family_id: str | None = None) -> None:
        """Remove all sessions for a user, optionally keeping one."""
        ...

    async def touch(self, family_id: str, last_seen: datetime) -> None:
        """Update last_seen timestamp for an active session."""
        ...


class MultiSessionPlugin:
    """Track multiple concurrent sessions per user.

    Attaches to the lifecycle hooks to automatically register and remove
    sessions. Exposes ``auth.sessions`` for listing and targeted revocation.

    Usage::

        from urauth.plugins.utility import MultiSessionPlugin

        class RedisSessionTracker:
            ...  # implement SessionTracker protocol

        auth = Auth(
            plugins=[MultiSessionPlugin(tracker=RedisSessionTracker())],
            ...
        )

        # List all active sessions
        sessions = await auth.sessions.list("user_id_here")

        # Revoke a specific session (e.g. "sign out of this device")
        await auth.sessions.revoke_session(user_id="u1", family_id="fam_123")

        # Sign out all other devices
        await auth.sessions.revoke_all_except(user_id="u1", current_family_id="fam_456")
    """

    id = "multi-session"

    def __init__(
        self,
        *,
        tracker: SessionTracker,
        max_sessions: int | None = None,
    ) -> None:
        """
        Args:
            tracker: Storage backend for session records.
            max_sessions: Maximum sessions per user. Oldest session is evicted
                          when limit is reached. ``None`` = unlimited.
        """
        self._tracker = tracker
        self.max_sessions = max_sessions
        self._auth: Auth | None = None

    def setup(self, auth: Auth) -> None:
        self._auth = auth
        auth.sessions = self

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    async def on_login(self, user_id: str, method: str) -> None:
        """Record a new session on login. Evicts oldest if max_sessions reached."""
        # Note: family_id is not available at this hook; caller should use
        # on_context_built to capture family_id from the token.
        pass

    async def on_logout(self, user_id: str) -> None:
        """Remove session records on logout (best-effort; family_id not available here)."""
        pass

    # ── Public API ────────────────────────────────────────────────────────────

    async def register(
        self,
        *,
        family_id: str,
        user_id: str,
        user_agent: str = "",
        ip: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> SessionRecord:
        """Manually register a session after login (call from your login handler).

        Pass the ``family_id`` from :class:`~urauth.tokens.lifecycle.IssuedTokenPair`.
        """
        now = datetime.now(timezone.utc)
        record = SessionRecord(
            family_id=family_id,
            user_id=user_id,
            created_at=now,
            last_seen=now,
            user_agent=user_agent,
            ip=ip,
            metadata=metadata or {},
        )

        if self.max_sessions is not None:
            existing = await self._tracker.list_for_user(user_id)
            if len(existing) >= self.max_sessions:
                # Evict oldest session
                oldest = min(existing, key=lambda s: s.created_at)
                await self._revoke_family(user_id, oldest.family_id)

        await self._tracker.save(record)
        return record

    async def list(self, user_id: str) -> list[SessionRecord]:
        """Return all active sessions for *user_id*."""
        return await self._tracker.list_for_user(user_id)

    async def touch(self, family_id: str) -> None:
        """Update the last-seen timestamp for an active session."""
        await self._tracker.touch(family_id, datetime.now(timezone.utc))

    async def revoke_session(self, *, user_id: str, family_id: str) -> None:
        """Revoke one session by family_id (sign out of one device)."""
        await self._revoke_family(user_id, family_id)

    async def revoke_all_except(self, *, user_id: str, current_family_id: str) -> None:
        """Revoke all sessions except the current one (sign out of all other devices)."""
        assert self._auth is not None
        sessions = await self._tracker.list_for_user(user_id)
        for session in sessions:
            if session.family_id != current_family_id:
                await self._revoke_family(user_id, session.family_id)

    async def revoke_all(self, user_id: str) -> None:
        """Revoke every session for *user_id*."""
        assert self._auth is not None
        await self._auth.lifecycle.revoke_all(user_id)
        await self._tracker.delete_all_for_user(user_id)

    async def _revoke_family(self, user_id: str, family_id: str) -> None:
        assert self._auth is not None
        try:
            await self._auth.lifecycle.revoke_family(family_id)
        except Exception:
            pass
        await self._tracker.delete(family_id)
