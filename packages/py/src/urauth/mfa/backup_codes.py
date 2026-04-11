"""Backup (recovery) codes for MFA fallback.

Codes are:
- Generated as random hex strings, formatted in groups for readability.
- Stored as SHA-256 hashes (same principle as API keys — never store plaintext).
- Single-use: consumed on first successful verification.

Storage is a Protocol so you plug in your own DB backend.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol


class BackupCodeStore(Protocol):
    """Interface for persisting backup code hashes."""

    async def save_hashes(self, user_id: str, hashes: list[str]) -> None:
        """Persist a fresh set of hashed backup codes, replacing any existing set."""
        ...

    async def consume(self, user_id: str, code_hash: str) -> bool:
        """Atomically remove *code_hash* if present. Return True if it existed."""
        ...

    async def remaining_count(self, user_id: str) -> int:
        """Return the number of unused codes left for the user."""
        ...


@dataclass(frozen=True, slots=True)
class GeneratedCodes:
    """Result of :func:`BackupCodes.generate`. Show ``codes`` to the user once."""

    codes: list[str]
    hashes: list[str]


class BackupCodes:
    """Generate and verify single-use backup codes.

    Args:
        store: A :class:`BackupCodeStore` backed by your database.
        count: Number of codes to generate per batch (default 10).
        group_size: Characters per display group (default 4, e.g. ``ab12-cd34``).
        code_length: Total raw hex chars before grouping (default 8).

    Usage::

        backup = BackupCodes(store=MyBackupCodeStore(db))

        # At MFA enrolment — show codes to user, store hashes
        generated = await backup.generate(user_id)
        # Display generated.codes → user writes them down

        # At login fallback
        ok = await backup.verify(user_id, code_from_user)
    """

    def __init__(
        self,
        store: BackupCodeStore,
        *,
        count: int = 10,
        group_size: int = 4,
        code_length: int = 8,
    ) -> None:
        self._store = store
        self._count = count
        self._group_size = group_size
        self._code_length = code_length

    def _format(self, raw: str) -> str:
        """Format raw hex as grouped code, e.g. ``ab12-cd34``."""
        groups = [raw[i : i + self._group_size] for i in range(0, len(raw), self._group_size)]
        return "-".join(groups)

    def _normalise(self, code: str) -> str:
        """Strip formatting for comparison."""
        return code.replace("-", "").replace(" ", "").lower()

    def _hash(self, raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    async def generate(self, user_id: str) -> GeneratedCodes:
        """Generate a fresh set of backup codes and persist their hashes.

        Any previously generated set for *user_id* is replaced.
        """
        raws = [secrets.token_hex(self._code_length // 2) for _ in range(self._count)]
        codes = [self._format(r) for r in raws]
        hashes = [self._hash(r) for r in raws]
        await self._store.save_hashes(user_id, hashes)
        return GeneratedCodes(codes=codes, hashes=hashes)

    async def verify(self, user_id: str, code: str) -> bool:
        """Verify and consume *code*. Returns ``True`` if valid (and removes it)."""
        normalised = self._normalise(code)
        code_hash = self._hash(normalised)
        return await self._store.consume(user_id, code_hash)

    async def remaining(self, user_id: str) -> int:
        """Return the number of unused backup codes the user has left."""
        return await self._store.remaining_count(user_id)
