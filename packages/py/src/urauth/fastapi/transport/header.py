from __future__ import annotations

from fastapi import Request, Response


class HeaderTransport:
    """Extract tokens from a custom header (e.g. X-API-Key)."""

    def __init__(self, header_name: str = "X-API-Key") -> None:
        self._header = header_name

    def extract_token(self, request: Request) -> str | None:
        return request.headers.get(self._header)

    def set_token(self, response: Response, token: str) -> None:
        response.headers[self._header] = token

    def delete_token(self, response: Response) -> None:
        pass
