# pyright: reportUnusedFunction=false
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from urauth.backends.base import UserFunctions
from urauth.config import AuthConfig
from urauth.exceptions import UnauthorizedError
from urauth.fastapi.transport.base import Transport
from urauth.tokens.lifecycle import IssueRequest, TokenLifecycle


class _LoginRequest(BaseModel):
    username: str
    password: str


class _TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class _RefreshRequest(BaseModel):
    refresh_token: str


def create_password_auth_router(
    user_fns: UserFunctions,
    lifecycle: TokenLifecycle,
    transport: Transport,
    config: AuthConfig,
) -> APIRouter:
    """Build a router with login, refresh, logout, and logout-all endpoints."""

    router = APIRouter(prefix=config.auth_prefix, tags=["auth"])

    @router.post("/login", response_model=_TokenResponse)
    async def login(body: _LoginRequest, request: Request, response: Response) -> _TokenResponse:
        user = await user_fns.get_by_username(body.username)
        if user is None:
            raise UnauthorizedError("Invalid credentials")

        if not await user_fns.verify_password(user, body.password):
            raise UnauthorizedError("Invalid credentials")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        pair = await lifecycle.issue(
            IssueRequest(
                user_id=str(user.id),
                roles=list(getattr(user, "roles", [])),
                fresh=True,
                session_metadata={
                    "ip": request.client.host if request.client else "unknown",
                    "user_agent": request.headers.get("user-agent", "unknown"),
                },
            )
        )

        transport.set_token(response, pair.access_token)
        return _TokenResponse(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
        )

    @router.post("/refresh", response_model=_TokenResponse)
    async def refresh(body: _RefreshRequest, response: Response) -> _TokenResponse:
        pair = await lifecycle.refresh(body.refresh_token)
        transport.set_token(response, pair.access_token)
        return _TokenResponse(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
        )

    _bearer = HTTPBearer(auto_error=False)

    @router.post("/logout", status_code=204)
    async def logout(
        request: Request,
        response: Response,
        _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> None:
        raw = transport.extract_token(request)
        if raw:
            await lifecycle.revoke(raw)
        transport.delete_token(response)

    @router.post("/logout-all", status_code=204)
    async def logout_all(
        request: Request,
        response: Response,
        _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> None:
        raw = transport.extract_token(request)
        if raw:
            try:
                claims = lifecycle.jwt.decode_token(raw)
            except Exception:
                transport.delete_token(response)
                return
            await lifecycle.revoke_all(claims["sub"])
        transport.delete_token(response)

    return router
