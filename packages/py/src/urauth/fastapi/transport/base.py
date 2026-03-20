from __future__ import annotations

from typing import Protocol

from fastapi import Request, Response


class Transport(Protocol):
    """Protocol for extracting/setting tokens from/on HTTP messages."""

    def extract_token(self, request: Request) -> str | None:
        """Extract a token string from the request, or return None."""
        ...

    def set_token(self, response: Response, token: str) -> None:
        """Attach a token to the response (e.g. set cookie or header)."""
        ...

    def delete_token(self, response: Response) -> None:
        """Remove the token from the response (e.g. clear cookie)."""
        ...
