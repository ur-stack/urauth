"""Last login method tracking plugin.

Records the authentication method used on each successful login.
Useful for security UIs ("Last signed in with Google 2 hours ago").
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from urauth.auth import Auth


@dataclass
class LoginRecord:
    """Records the method and timestamp of a successful login."""

    user_id: str
    method: str
    timestamp: datetime
    ip: str = ""
    user_agent: str = ""


class LastLoginStore(Protocol):
    """Protocol for persisting the most recent login record per user."""

    async def save(self, record: LoginRecord) -> None:
        """Persist or overwrite the last login record for the user."""
        ...

    async def get(self, user_id: str) -> LoginRecord | None:
        """Fetch the last login record for *user_id*."""
        ...


class LastLoginPlugin:
    """Track the most recent authentication method per user.

    Hooks into ``on_login`` to automatically record method + timestamp.
    Access the last login info via ``auth.last_login.get(user_id)``.

    Usage::

        from urauth.plugins.utility import LastLoginPlugin

        class MyLastLoginStore:
            async def save(self, record): ...
            async def get(self, user_id): ...

        auth = Auth(
            plugins=[LastLoginPlugin(store=MyLastLoginStore())],
            ...
        )

        record = await auth.last_login.get("user_id_here")
        # record.method → "password" | "oauth" | "otp" | "magic_link"
        # record.timestamp → datetime(...)
    """

    id = "last-login"

    def __init__(self, *, store: LastLoginStore) -> None:
        self._store = store

    def setup(self, auth: Auth) -> None:
        auth.last_login = self

    async def on_login(self, user_id: str, method: str) -> None:
        """Hook: called after every successful login."""
        record = LoginRecord(
            user_id=user_id,
            method=method,
            timestamp=datetime.now(timezone.utc),
        )
        await self._store.save(record)

    async def get(self, user_id: str) -> LoginRecord | None:
        """Return the last login record for *user_id*, or ``None``."""
        return await self._store.get(user_id)
