"""Account lifecycle operations — suspend/ban, reactivation, GDPR deletion.

All operations are defined as Protocols so the application wires them to its
own database layer. urauth provides the orchestration logic; storage is yours.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


# ── Storage protocols ─────────────────────────────────────────────────────────

class AccountStore(Protocol):
    """Minimal interface for account state mutations."""

    async def set_active(self, user_id: str, *, active: bool) -> None:
        """Activate or deactivate (suspend/ban) a user account."""
        ...

    async def delete_user(self, user_id: str) -> None:
        """Permanently delete all user data (GDPR right-to-erasure)."""
        ...

    async def anonymize_user(self, user_id: str) -> None:
        """Replace PII with anonymised placeholders instead of hard-deleting."""
        ...


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class SuspendResult:
    user_id: str
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DeletionResult:
    user_id: str
    anonymized: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Lifecycle manager ─────────────────────────────────────────────────────────

class AccountLifecycle:
    """Orchestrates account state transitions.

    Args:
        store: An :class:`AccountStore` implementation backed by your database.

    Usage::

        lifecycle = AccountLifecycle(store=MyAccountStore(db))

        # Suspend a user
        result = await lifecycle.suspend(user_id, reason="abuse report #1234")

        # GDPR deletion
        result = await lifecycle.delete(user_id)

        # Or anonymise instead of hard-delete
        result = await lifecycle.delete(user_id, anonymize=True)
    """

    def __init__(self, store: AccountStore) -> None:
        self._store = store

    async def suspend(self, user_id: str, *, reason: str | None = None) -> SuspendResult:
        """Deactivate a user account (soft ban)."""
        await self._store.set_active(user_id, active=False)
        return SuspendResult(user_id=user_id, reason=reason)

    async def reactivate(self, user_id: str) -> None:
        """Re-enable a previously suspended account."""
        await self._store.set_active(user_id, active=True)

    async def delete(self, user_id: str, *, anonymize: bool = False) -> DeletionResult:
        """Permanently remove or anonymise a user (GDPR right-to-erasure).

        Args:
            user_id: The user to delete.
            anonymize: If ``True``, replace PII with placeholders instead of
                       hard-deleting the row (useful when you must keep audit
                       records but cannot store the original PII).
        """
        if anonymize:
            await self._store.anonymize_user(user_id)
        else:
            await self._store.delete_user(user_id)
        return DeletionResult(user_id=user_id, anonymized=anonymize)
