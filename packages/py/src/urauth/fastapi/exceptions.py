"""Exception handlers mapping core AuthError → HTTP responses."""

from __future__ import annotations

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from urauth.exceptions import AuthError


def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    """Convert a core AuthError into a JSONResponse."""
    headers: dict[str, str] = {}
    if exc.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers that map core exceptions to HTTP responses."""
    app.add_exception_handler(AuthError, auth_error_handler)  # type: ignore[arg-type]
