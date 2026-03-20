from __future__ import annotations

from fastapi import Request, Response

from urauth.fastapi.transport.base import Transport


class HybridTransport:
    """Try bearer header first, then fall back to cookie."""

    def __init__(self, *transports: Transport) -> None:
        if not transports:
            raise ValueError("At least one transport is required")
        self._transports = transports

    def extract_token(self, request: Request) -> str | None:
        for t in self._transports:
            token = t.extract_token(request)
            if token is not None:
                return token
        return None

    def set_token(self, response: Response, token: str) -> None:
        for t in self._transports:
            t.set_token(response, token)

    def delete_token(self, response: Response) -> None:
        for t in self._transports:
            t.delete_token(response)
