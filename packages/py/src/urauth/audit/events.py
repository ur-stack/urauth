"""Structured audit event system for urauth.

Events are emitted at key authentication/authorization points.
They NEVER contain secrets, raw tokens, or passwords.

Usage::

    from urauth.audit import AuthEvent, AuthEventHandler

    class MyHandler(AuthEventHandler):
        async def handle(self, event: AuthEvent) -> None:
            logger.info("auth_event", event_type=event.event_type, user_id=event.user_id)

    auth = Auth(config=config, event_handler=MyHandler())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """An audit event emitted by urauth. Never contains secrets or raw tokens."""

    event_type: str
    user_id: str | None = None
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class AuthEventHandler(Protocol):
    """Protocol for handling auth events."""

    async def handle(self, event: AuthEvent) -> None: ...


class NullEventHandler:
    """Default no-op event handler. Zero overhead."""

    async def handle(self, event: AuthEvent) -> None:
        pass


class StructlogEventHandler:
    """Event handler that emits structured log entries via structlog.

    Requires ``pip install urauth[audit]``. Each AuthEvent becomes a
    structlog log entry at INFO level with all event fields bound.

    Usage::

        from urauth.audit import StructlogEventHandler
        auth = Auth(..., event_handler=StructlogEventHandler())
    """

    def __init__(self, logger_name: str = "urauth.audit") -> None:
        try:
            import structlog  # noqa: F401
        except ImportError:
            raise ImportError(
                "structlog is required for StructlogEventHandler. "
                "Install with: pip install urauth[audit]"
            ) from None
        self._logger_name = logger_name

    async def handle(self, event: AuthEvent) -> None:
        import structlog

        log = structlog.get_logger(self._logger_name)
        await log.ainfo(
            event.event_type,
            user_id=event.user_id,
            timestamp=event.timestamp,
            **event.metadata,
        )
