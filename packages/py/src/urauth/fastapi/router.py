from __future__ import annotations

import uuid

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from urauth.backends.base import TokenStore, UserFunctions
from urauth.config import AuthConfig
from urauth.exceptions import UnauthorizedError
from urauth.fastapi.transport.base import Transport
from urauth.tokens.jwt import TokenService
from urauth.tokens.refresh import RefreshService
from urauth.tokens.revocation import RevocationService


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
    token_service: TokenService,
    token_store: TokenStore,
    transport: Transport,
    config: AuthConfig,
) -> APIRouter:
    """Build a router with login, refresh, logout, and logout-all endpoints."""

    router = APIRouter(prefix=config.auth_prefix, tags=["auth"])
    refresh_service = RefreshService(token_service, token_store, config)
    revocation_service = RevocationService(token_store)

    @router.post("/login", response_model=_TokenResponse)
    async def login(body: _LoginRequest, response: Response) -> _TokenResponse:
        user = await user_fns.get_by_username(body.username)
        if user is None:
            raise UnauthorizedError("Invalid credentials")

        if not await user_fns.verify_password(user, body.password):
            raise UnauthorizedError("Invalid credentials")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        user_id = str(user.id)
        roles = list(getattr(user, "roles", []))
        family_id = uuid.uuid4().hex

        pair = token_service.create_token_pair(
            user_id,
            roles=roles,
            fresh=True,
            family_id=family_id,
        )

        # Track tokens
        access_claims = token_service.decode_token(pair.access_token)
        refresh_claims = token_service.decode_token(pair.refresh_token)
        await token_store.add_token(
            jti=access_claims["jti"],
            user_id=user_id,
            token_type="access",
            expires_at=access_claims["exp"],
            family_id=family_id,
        )
        await token_store.add_token(
            jti=refresh_claims["jti"],
            user_id=user_id,
            token_type="refresh",
            expires_at=refresh_claims["exp"],
            family_id=family_id,
        )

        transport.set_token(response, pair.access_token)
        return _TokenResponse(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
        )

    @router.post("/refresh", response_model=_TokenResponse)
    async def refresh(body: _RefreshRequest, response: Response) -> _TokenResponse:
        pair = await refresh_service.rotate(body.refresh_token)
        transport.set_token(response, pair.access_token)
        return _TokenResponse(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
        )

    @router.post("/logout", status_code=204)
    async def logout(request: Request, response: Response) -> None:
        raw = transport.extract_token(request)
        if raw:
            try:
                claims = token_service.decode_token(raw)
                await revocation_service.revoke(claims["jti"], claims["exp"])
            except Exception:
                pass
        transport.delete_token(response)

    @router.post("/logout-all", status_code=204)
    async def logout_all(request: Request, response: Response) -> None:
        raw = transport.extract_token(request)
        if raw:
            try:
                claims = token_service.decode_token(raw)
                await revocation_service.revoke_all_for_user(claims["sub"])
            except Exception:
                pass
        transport.delete_token(response)

    return router
