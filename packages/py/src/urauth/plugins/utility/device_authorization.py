"""Device Authorization Grant plugin (RFC 8628).

Implements the OAuth 2.0 Device Authorization Grant for input-constrained
devices (smart TVs, CLIs, IoT). The device displays a short code; the user
approves it on a separate browser.

Flow:
1. Device calls ``start()`` → gets ``device_code``, ``user_code``, ``verification_uri``.
2. Device polls ``poll()`` every ``interval`` seconds.
3. User visits ``verification_uri`` and enters ``user_code``.
4. Application calls ``approve()`` to link the code to a user_id.
5. Next device poll returns the access + refresh tokens.

Usage::

    from urauth.plugins.utility import DeviceAuthorizationPlugin

    class MyDeviceStore:
        ...  # implement DeviceStore protocol

    auth = Auth(
        plugins=[
            DeviceAuthorizationPlugin(
                store=MyDeviceStore(),
                verification_uri="https://myapp.com/device",
                expires_in=600,
                interval=5,
            )
        ],
        ...
    )

    # Device endpoint
    result = await auth.device_auth.start(scopes=["read"])

    # Poll endpoint (called by device every `interval` seconds)
    tokens = await auth.device_auth.poll(device_code="...")

    # User approval endpoint
    await auth.device_auth.approve(user_code="AB12CD", user_id="u1")
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from urauth.auth import Auth


@dataclass
class DeviceSession:
    """State for one pending device authorization."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_at: datetime
    interval: int
    scopes: list[str]
    user_id: str | None = None  # Set when user approves
    approved: bool = False
    denied: bool = False


@dataclass
class DeviceStartResult:
    """Response returned to the device when starting a flow."""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


class DeviceStore(Protocol):
    """Protocol for persisting device authorization sessions."""

    async def save(self, session: DeviceSession) -> None: ...
    async def get_by_device_code(self, device_code: str) -> DeviceSession | None: ...
    async def get_by_user_code(self, user_code: str) -> DeviceSession | None: ...
    async def update(self, session: DeviceSession) -> None: ...
    async def delete(self, device_code: str) -> None: ...


class DeviceAuthorizationPlugin:
    """OAuth 2.0 Device Authorization Grant (RFC 8628)."""

    id = "device-authorization"

    def __init__(
        self,
        *,
        store: DeviceStore,
        verification_uri: str,
        expires_in: int = 600,
        interval: int = 5,
        user_code_length: int = 8,
    ) -> None:
        self._store = store
        self.verification_uri = verification_uri
        self.expires_in = expires_in
        self.interval = interval
        self.user_code_length = user_code_length
        self._auth: Auth | None = None

    def setup(self, auth: Auth) -> None:
        self._auth = auth
        auth.device_auth = self

    def _new_user_code(self) -> str:
        """Generate a human-friendly code (no ambiguous chars: 0/O, I/1/L)."""
        alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        raw = "".join(secrets.choice(alphabet) for _ in range(self.user_code_length))
        # Format as XXXX-XXXX for readability
        mid = self.user_code_length // 2
        return f"{raw[:mid]}-{raw[mid:]}"

    async def start(self, *, scopes: list[str] | None = None) -> DeviceStartResult:
        """Start a device authorization flow. Called by the device."""
        import datetime as dt

        session = DeviceSession(
            device_code=secrets.token_urlsafe(32),
            user_code=self._new_user_code(),
            verification_uri=self.verification_uri,
            expires_at=datetime.now(timezone.utc) + dt.timedelta(seconds=self.expires_in),
            interval=self.interval,
            scopes=scopes or [],
        )
        await self._store.save(session)
        return DeviceStartResult(
            device_code=session.device_code,
            user_code=session.user_code,
            verification_uri=self.verification_uri,
            expires_in=self.expires_in,
            interval=self.interval,
        )

    async def approve(self, *, user_code: str, user_id: str) -> None:
        """Approve a pending device request. Called after the user enters the code."""
        session = await self._store.get_by_user_code(user_code.upper().replace(" ", "-"))
        if session is None:
            raise ValueError("Invalid or expired user code.")
        if datetime.now(timezone.utc) > session.expires_at:
            await self._store.delete(session.device_code)
            raise ValueError("Device code has expired.")
        session.user_id = user_id
        session.approved = True
        await self._store.update(session)

    async def deny(self, *, user_code: str) -> None:
        """Deny a pending device request."""
        session = await self._store.get_by_user_code(user_code)
        if session is not None:
            session.denied = True
            await self._store.update(session)

    async def poll(self, device_code: str) -> Any:
        """Poll for approval. Returns token pair when approved, ``None`` while pending.

        Raises:
            ValueError: Device code expired, denied, or invalid.
        """
        assert self._auth is not None
        session = await self._store.get_by_device_code(device_code)
        if session is None:
            raise ValueError("Invalid device code.")
        if datetime.now(timezone.utc) > session.expires_at:
            await self._store.delete(device_code)
            raise ValueError("Device code expired.")
        if session.denied:
            await self._store.delete(device_code)
            raise ValueError("Device authorization was denied.")
        if not session.approved or session.user_id is None:
            return None  # authorization_pending

        # Issue tokens
        from urauth.tokens.lifecycle import IssueRequest

        issued = await self._auth.lifecycle.issue(
            IssueRequest(user_id=session.user_id, scopes=session.scopes)
        )
        await self._store.delete(device_code)
        return issued
