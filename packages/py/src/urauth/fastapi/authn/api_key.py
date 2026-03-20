"""API key authentication dependency."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request

from urauth.exceptions import UnauthorizedError
from urauth.fastapi.transport.header import HeaderTransport


class APIKeyAuth:
    """Validate API keys from a custom header.

    The ``lookup`` callable receives an API key string and returns
    the associated user, or None if invalid.
    """

    def __init__(
        self,
        lookup: Callable[[str], Any],
        *,
        header_name: str = "X-API-Key",
    ) -> None:
        self._lookup = lookup
        self._transport = HeaderTransport(header_name)

    def dependency(self) -> Callable:
        lookup = self._lookup
        transport = self._transport

        async def _resolve(request: Request) -> Any:
            key = transport.extract_token(request)
            if key is None:
                raise UnauthorizedError("API key required")

            # Support both sync and async lookups
            import asyncio

            if asyncio.iscoroutinefunction(lookup):
                user = await lookup(key)
            else:
                user = lookup(key)

            if user is None:
                raise UnauthorizedError("Invalid API key")
            return user

        return _resolve
