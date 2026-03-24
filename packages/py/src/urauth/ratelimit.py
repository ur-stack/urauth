# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportAttributeAccessIssue=false, reportUntypedBaseClass=false
"""Framework-agnostic rate limiting using pyrate-limiter.

Provides key extraction strategies and a RateLimiter facade that works
with any framework. Framework adapters (FastAPI, etc.) wrap this for
Depends() / middleware integration.

Requires: ``pip install pyrate-limiter``
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

try:
    from pyrate_limiter import Limiter  # type: ignore[reportMissingImports]
except ImportError:
    Limiter = None  # type: ignore[assignment,misc]


class KeyStrategy(StrEnum):
    """Built-in key extraction strategies for rate limiting."""

    IP = "ip"
    IDENTITY = "identity"
    SESSION = "session"
    JWT = "jwt"


class RateLimiter:
    """Framework-agnostic rate limiter wrapping pyrate-limiter.

    Usage::

        from pyrate_limiter import Duration, Rate
        from urauth.ratelimit import RateLimiter, KeyStrategy

        limiter = RateLimiter(
            rates=[Rate(100, Duration.MINUTE)],
            key=KeyStrategy.IP,
        )

        # Check rate limit with a raw key string
        allowed = await limiter.check("192.168.1.1")

        # Or pass structured info for built-in key strategies
        allowed = await limiter.check_request(
            ip="192.168.1.1",
            user_id="user-42",
            session_id="sess-abc",
            jwt_sub="user-42",
        )
    """

    def __init__(
        self,
        rates: list[Any],
        *,
        key: KeyStrategy | str = KeyStrategy.IP,
        key_func: Any | None = None,
        bucket: Any | None = None,
        prefix: str = "rl",
    ) -> None:
        """
        Args:
            rates: List of ``pyrate_limiter.Rate`` objects.
            key: Built-in key strategy or custom string prefix.
            key_func: Custom callable ``(ip, user_id, session_id, jwt_sub, **kw) -> str``.
                      Overrides ``key`` when provided.
            bucket: Custom bucket (e.g. ``RedisBucket``). Defaults to in-memory.
            prefix: Key prefix to namespace rate limit buckets.
        """
        if Limiter is None:
            raise ImportError("pyrate-limiter is required for rate limiting. Install with: pip install pyrate-limiter")

        if bucket is not None:
            self._limiter = Limiter(bucket)
        else:
            self._limiter = Limiter(*rates) if len(rates) == 1 else Limiter(rates)

        self._key_strategy = key
        self._key_func = key_func
        self._prefix = prefix

    def resolve_key(
        self,
        *,
        ip: str | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        jwt_sub: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Resolve a rate limit key from structured info."""
        if self._key_func is not None:
            return self._key_func(ip=ip, user_id=user_id, session_id=session_id, jwt_sub=jwt_sub, **kwargs)

        match self._key_strategy:
            case KeyStrategy.IP:
                return f"{self._prefix}:ip:{ip or 'unknown'}"
            case KeyStrategy.IDENTITY:
                return f"{self._prefix}:user:{user_id or ip or 'unknown'}"
            case KeyStrategy.SESSION:
                return f"{self._prefix}:sess:{session_id or 'unknown'}"
            case KeyStrategy.JWT:
                return f"{self._prefix}:jwt:{jwt_sub or 'unknown'}"
            case _:
                # Custom string strategy — use as-is with the available info
                return f"{self._prefix}:{self._key_strategy}:{user_id or ip or 'unknown'}"

    async def check(self, key: str) -> bool:
        """Check rate limit for a raw key string. Returns True if allowed."""
        return await self._limiter.try_acquire_async(key, blocking=False)

    async def check_request(
        self,
        *,
        ip: str | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        jwt_sub: str | None = None,
        **kwargs: Any,
    ) -> bool:
        """Check rate limit using structured request info. Returns True if allowed."""
        key = self.resolve_key(ip=ip, user_id=user_id, session_id=session_id, jwt_sub=jwt_sub, **kwargs)
        return await self.check(key)
