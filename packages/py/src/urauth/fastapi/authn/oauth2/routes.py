"""Router factory for OAuth login/callback per provider."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Request, Response
from starlette.responses import RedirectResponse

from urauth.authn.oauth2.client import OAuthManager
from urauth.backends.base import TokenStore, UserFunctions
from urauth.config import AuthConfig
from urauth.fastapi.authn.oauth2.account_link import AccountLinker
from urauth.fastapi.transport.base import Transport
from urauth.tokens.jwt import TokenService


def create_oauth_router(
    *,
    provider: str,
    oauth_manager: OAuthManager,
    token_service: TokenService,
    token_store: TokenStore,
    user_fns: UserFunctions,
    transport: Transport,
    config: AuthConfig,
    callback_url: str | None = None,
) -> APIRouter:
    router = APIRouter(prefix=config.auth_prefix, tags=["oauth"])
    linker = AccountLinker(user_fns)

    @router.get(f"/oauth/{provider}/login")
    async def oauth_login(request: Request) -> Any:
        redirect_uri = callback_url or str(request.url_for(f"oauth_{provider}_callback"))

        state, code_verifier, _ = oauth_manager.build_authorize_params(provider, redirect_uri)
        request.session["oauth_state"] = state
        request.session["oauth_provider"] = provider
        request.session["oauth_code_verifier"] = code_verifier

        url = await oauth_manager.authorize_redirect_url(provider, redirect_uri, state, code_verifier)
        return RedirectResponse(url=url)

    @router.get(f"/oauth/{provider}/callback", name=f"oauth_{provider}_callback")
    async def oauth_callback(request: Request, response: Response) -> dict[str, Any]:
        # Validate state
        expected_state = request.session.get("oauth_state")
        received_state = request.query_params.get("state")
        if not expected_state or expected_state != received_state:
            raise ValueError("Invalid OAuth state parameter — possible CSRF attack")

        code = request.query_params.get("code")
        if not code:
            error = request.query_params.get("error", "unknown")
            raise ValueError(f"OAuth authorization failed: {error}")

        code_verifier = request.session.get("oauth_code_verifier", "")

        # Clean up session
        request.session.pop("oauth_state", None)
        request.session.pop("oauth_provider", None)
        request.session.pop("oauth_code_verifier", None)

        redirect_uri = callback_url or str(request.url_for(f"oauth_{provider}_callback"))

        info = await oauth_manager.exchange_code(provider, code, redirect_uri, code_verifier)
        user = await linker.find_or_create(info)

        user_id = str(user.id)
        roles = list(getattr(user, "roles", []))
        family_id = uuid.uuid4().hex

        pair = token_service.create_token_pair(user_id, roles=roles, family_id=family_id)

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
        return {
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "token_type": "bearer",
        }

    return router
