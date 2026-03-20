from __future__ import annotations

from fastapi import Request, Response


class BearerTransport:
    """Extract tokens from the Authorization: Bearer header."""

    def extract_token(self, request: Request) -> str | None:
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        return None

    def set_token(self, response: Response, token: str) -> None:
        response.headers["Authorization"] = f"Bearer {token}"

    def delete_token(self, response: Response) -> None:
        pass  # Bearer tokens are stateless; nothing to clear
