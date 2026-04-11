"""API key generation, verification, and lifecycle management.

Design:
- Keys are generated as ``<prefix>_<random>`` (e.g. ``sk_live_xK3mN...``).
- Only the SHA-256 hash of the random part is stored — the full key is shown
  once at creation and never again (like GitHub PATs).
- Expiry and scopes are stored alongside the hash.
- Verification is a single hash lookup: O(1), no timing oracle.

Storage is a Protocol so you plug in your own DB backend.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


# ── Storage protocol ──────────────────────────────────────────────────────────

class ApiKeyStore(Protocol):
    """Interface for persisting API key records."""

    async def save(self, record: "ApiKeyRecord") -> None:
        """Persist a new key record."""
        ...

    async def get_by_hash(self, key_hash: str) -> "ApiKeyRecord | None":
        """Look up a key record by its hash. Returns ``None`` if not found."""
        ...

    async def revoke(self, key_id: str) -> None:
        """Mark a key as revoked."""
        ...

    async def list_for_user(self, user_id: str) -> list["ApiKeyRecord"]:
        """Return all key records for a user (for management UIs)."""
        ...


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class ApiKeyRecord:
    """Stored representation of an API key (never the raw secret)."""

    key_id: str
    user_id: str
    key_hash: str          # SHA-256 of the raw key
    prefix: str            # human-readable prefix shown in the UI
    scopes: list[str]      # e.g. ["read", "write"] or ["user:read"]
    created_at: datetime
    expires_at: datetime | None = None
    revoked: bool = False
    name: str = ""         # human label, e.g. "CI deploy key"
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        if self.revoked:
            return False
        if self.expires_at and datetime.now(tz=timezone.utc) > self.expires_at:
            return False
        return True


@dataclass(frozen=True, slots=True)
class CreatedApiKey:
    """Returned once at creation. ``raw_key`` is never stored and cannot be recovered."""

    raw_key: str
    record: ApiKeyRecord


# ── Manager ───────────────────────────────────────────────────────────────────

class ApiKeyManager:
    """Create, verify, and revoke API keys.

    Args:
        store: An :class:`ApiKeyStore` implementation backed by your database.
        prefix: Key prefix shown to users (e.g. ``"sk_live"``). Defaults to ``"urauth"``.
        key_bytes: Length of the random key material in bytes (default: 32 → 43 chars base64url).

    Usage::

        manager = ApiKeyManager(store=MyApiKeyStore(db), prefix="sk_live")

        # Create
        created = await manager.create(
            user_id="usr_123",
            scopes=["task:read", "task:write"],
            name="CI deploy key",
        )
        # Show created.raw_key to the user ONCE, then discard it.

        # Verify on each API request
        result = await manager.verify("sk_live_xK3mN...")
        if result is None:
            raise Unauthorized()
        user_id, scopes = result.user_id, result.scopes
    """

    def __init__(
        self,
        store: ApiKeyStore,
        prefix: str = "urauth",
        key_bytes: int = 32,
    ) -> None:
        self._store = store
        self._prefix = prefix
        self._key_bytes = key_bytes

    def _hash(self, raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    async def create(
        self,
        user_id: str,
        *,
        scopes: list[str] | None = None,
        name: str = "",
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CreatedApiKey:
        """Generate a new API key and persist its hash.

        The returned :attr:`~CreatedApiKey.raw_key` must be shown to the user
        immediately — it cannot be recovered later.
        """
        random_part = secrets.token_urlsafe(self._key_bytes)
        raw_key = f"{self._prefix}_{random_part}"
        key_hash = self._hash(raw_key)
        key_id = secrets.token_hex(16)

        record = ApiKeyRecord(
            key_id=key_id,
            user_id=user_id,
            key_hash=key_hash,
            prefix=self._prefix,
            scopes=scopes or [],
            created_at=datetime.now(tz=timezone.utc),
            expires_at=expires_at,
            name=name,
            metadata=metadata or {},
        )
        await self._store.save(record)
        return CreatedApiKey(raw_key=raw_key, record=record)

    async def verify(self, raw_key: str) -> ApiKeyRecord | None:
        """Verify a raw API key and return its record, or ``None`` if invalid.

        Never raises — returns ``None`` for any failure so callers cannot
        distinguish "not found" from "revoked" (prevents enumeration).
        """
        key_hash = self._hash(raw_key)
        record = await self._store.get_by_hash(key_hash)
        if record is None or not record.is_valid():
            return None
        return record

    async def revoke(self, key_id: str) -> None:
        """Revoke a key by its ID."""
        await self._store.revoke(key_id)

    async def list_for_user(self, user_id: str) -> list[ApiKeyRecord]:
        """Return all key records for a user (metadata only, no raw keys)."""
        return await self._store.list_for_user(user_id)
