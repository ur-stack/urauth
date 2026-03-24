# pyright: reportUnusedFunction=false, reportUnusedClass=false
"""Auto-generate FastAPI routes from pipeline configuration.

The :class:`PipelineRouterBuilder` inspects the
:class:`~urauth.pipeline.Pipeline` and creates all necessary endpoints
for login methods, lifecycle management, MFA, password reset, account
linking, and passkey operations.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from urauth.auth import Auth, maybe_await
from urauth.authn.oauth2.client import OAuthManager
from urauth.context import AuthContext
from urauth.exceptions import ForbiddenError, UnauthorizedError
from urauth.fastapi.transport.base import Transport
from urauth.pipeline import (
    MFA,
    JWTStrategy,
    MagicLinkLogin,
    OAuthLogin,
    OTPLogin,
    PasskeyLogin,
    PasswordLogin,
    PasswordReset,
    Pipeline,
    SessionStrategy,
)
from urauth.tokens.refresh import RefreshService

# ── Shared request / response schemas ────────────────────────────


class _IdentifierLoginRequest(BaseModel):
    identifier: str
    password: str


class _UsernameLoginRequest(BaseModel):
    username: str
    password: str


class _TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class _MFARequiredResponse(BaseModel):
    mfa_token: str
    mfa_required: bool = True
    methods: list[str] = []


class _RefreshRequest(BaseModel):
    refresh_token: str


class _MagicLinkRequest(BaseModel):
    email: str


class _MagicLinkVerify(BaseModel):
    token: str


class _OTPVerifyRequest(BaseModel):
    username: str
    code: str


class _MFAVerifyRequest(BaseModel):
    mfa_token: str
    method: str
    code: str


class _MFAEnrollRequest(BaseModel):
    method: str


class _ForgotPasswordRequest(BaseModel):
    email: str


class _ResetConfirmRequest(BaseModel):
    token: str


class _ResetCompleteRequest(BaseModel):
    reset_session: str
    new_password: str


class _LinkPhoneRequest(BaseModel):
    phone: str


class _LinkEmailRequest(BaseModel):
    email: str


class _PasskeyCredential(BaseModel):
    credential: dict[str, Any]


class _PasskeyLoginBegin(BaseModel):
    pass


# ── Credential issuance (strategy-dependent) ────────────────────


async def _issue_credentials(
    auth: Auth,
    user: Any,
    strategy: Any,
    transport: Transport,
    request: Request,
    response: Response,
    *,
    mfa: MFA | None = None,
) -> dict[str, Any]:
    """Issue credentials after successful authentication.

    If MFA is configured and the user is enrolled, returns an
    ``mfa_token`` instead of full credentials.
    """
    # Check MFA before issuing full credentials
    if mfa is not None:
        needs_mfa = mfa.required or await maybe_await(auth.is_mfa_enrolled(user))
        if needs_mfa:
            mfa_token = auth.token_service.create_access_token(
                str(user.id),
                extra_claims={"type": "mfa", "mfa_pending": True},
                fresh=True,
            )
            methods = await maybe_await(auth.get_mfa_methods(user))
            return {"mfa_token": mfa_token, "mfa_required": True, "methods": methods}

    if isinstance(strategy, JWTStrategy):
        return await _issue_jwt(auth, user, strategy, transport, request, response)

    if isinstance(strategy, SessionStrategy):
        return await _issue_session(auth, user, strategy, response)

    # BasicAuth / APIKey don't issue credentials
    return {"detail": "Authenticated"}


async def _issue_jwt(
    auth: Auth,
    user: Any,
    strategy: JWTStrategy,
    transport: Transport,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Create JWT token pair and track if revocable."""
    user_id = str(user.id)
    roles = [str(r) for r in getattr(user, "roles", [])]
    family_id = uuid.uuid4().hex

    pair = auth.token_service.create_token_pair(
        user_id,
        roles=roles,
        fresh=True,
        family_id=family_id,
    )

    if strategy.revocable:
        access_claims = auth.token_service.decode_token(pair.access_token)
        refresh_claims = auth.token_service.decode_token(pair.refresh_token)
        metadata = {
            "ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
        }
        await auth.token_store.add_token(
            jti=access_claims["jti"],
            user_id=user_id,
            token_type="access",
            expires_at=access_claims["exp"],
            family_id=family_id,
            metadata=metadata,
        )
        await auth.token_store.add_token(
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


async def _issue_session(
    auth: Auth,
    user: Any,
    strategy: SessionStrategy,
    response: Response,
) -> dict[str, Any]:
    """Create a server-side session and set cookie."""
    if auth.session_store is None:
        raise RuntimeError("SessionStrategy requires a session_store on Auth")

    session_id = secrets.token_urlsafe(32)
    user_id = str(user.id)
    await auth.session_store.create(
        session_id,
        user_id,
        data={"roles": [str(r) for r in getattr(user, "roles", [])]},
        ttl=auth.config.session_ttl,
    )
    response.set_cookie(
        key=strategy.cookie_name,
        value=session_id,
        max_age=auth.config.session_ttl,
        httponly=auth.config.session_cookie_httponly,
        secure=auth.config.session_cookie_secure,
        samesite=auth.config.session_cookie_samesite,
    )
    return {"session_id": session_id}


# ── Router builder ───────────────────────────────────────────────


class PipelineRouterBuilder:
    """Builds a complete FastAPI router from pipeline configuration.

    Usage::

        builder = PipelineRouterBuilder(auth, pipeline, transport)
        router = builder.build()
        app.include_router(router)
    """

    def __init__(
        self,
        auth: Auth,
        pipeline: Pipeline,
        transport: Transport,
        resolver: Any = None,
    ) -> None:
        self._auth = auth
        self._pipeline = pipeline
        self._transport = transport
        self._resolver = resolver

    def build(self) -> APIRouter:
        """Build the combined router with all enabled endpoints."""
        router = APIRouter(prefix=self._auth.config.auth_prefix, tags=["auth"])

        # Login method routes
        for method in self._pipeline.enabled_methods():
            if isinstance(method, PasswordLogin):
                self._add_password_routes(router)
            elif isinstance(method, OAuthLogin):
                self._add_oauth_routes(router, method)
            elif isinstance(method, MagicLinkLogin):
                self._add_magic_link_routes(router, method)
            elif isinstance(method, OTPLogin):
                self._add_otp_routes(router, method)
            else:
                self._add_passkey_routes(router, method)

        # MFA routes
        if self._pipeline.has_mfa:
            self._add_mfa_routes(router, self._pipeline.mfa)  # type: ignore[arg-type]

        # Password reset routes
        if self._pipeline.has_password_reset:
            self._add_password_reset_routes(router, self._pipeline.password_reset_config)

        # Account linking routes
        if self._pipeline.has_account_linking:
            self._add_account_linking_routes(router)

        # Strategy lifecycle routes (refresh, logout)
        strategy = self._pipeline.strategy
        if isinstance(strategy, JWTStrategy):
            self._add_jwt_lifecycle_routes(router, strategy)
        elif isinstance(strategy, SessionStrategy):
            self._add_session_lifecycle_routes(router, strategy)

        return router

    # ── Password login ───────────────────────────────────────────

    def _add_password_routes(self, router: APIRouter) -> None:
        auth = self._auth
        strategy = self._pipeline.strategy
        transport = self._transport
        mfa = self._pipeline.mfa
        identifiers = self._pipeline.identifiers
        use_identifier = identifiers.phone or identifiers.username or not identifiers.email

        if use_identifier:

            @router.post("/login")
            async def login_identifier(
                body: _IdentifierLoginRequest, request: Request, response: Response
            ) -> dict[str, Any]:
                user = await maybe_await(auth.get_user_by_identifier(body.identifier))
                if user is None:
                    raise UnauthorizedError("Invalid credentials")
                valid = await maybe_await(auth.verify_password(user, body.password))
                if not valid:
                    raise UnauthorizedError("Invalid credentials")
                if not getattr(user, "is_active", True):
                    raise UnauthorizedError("Inactive user")
                return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=mfa)

        else:

            @router.post("/login")
            async def login_username(
                body: _UsernameLoginRequest, request: Request, response: Response
            ) -> dict[str, Any]:
                user = await maybe_await(auth.get_user_by_username(body.username))
                if user is None:
                    raise UnauthorizedError("Invalid credentials")
                valid = await maybe_await(auth.verify_password(user, body.password))
                if not valid:
                    raise UnauthorizedError("Invalid credentials")
                if not getattr(user, "is_active", True):
                    raise UnauthorizedError("Inactive user")
                return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=mfa)

    # ── OAuth login ──────────────────────────────────────────────

    def _add_oauth_routes(self, router: APIRouter, oauth: OAuthLogin) -> None:
        auth = self._auth
        strategy = self._pipeline.strategy
        transport = self._transport
        mfa = self._pipeline.mfa

        manager = OAuthManager()
        for provider in oauth.providers:
            kwargs: dict[str, Any] = {}
            if provider.scopes:
                kwargs["client_kwargs"] = {"scope": " ".join(provider.scopes)}
            kwargs.update(provider.extra)
            manager.register(
                provider.name,
                client_id=provider.client_id,
                client_secret=provider.client_secret,
                **kwargs,
            )

        @router.get("/oauth/{provider}/authorize")
        async def oauth_authorize(provider: str, request: Request) -> dict[str, Any]:
            redirect_uri = str(request.url_for("oauth_callback", provider=provider))
            state, code_verifier, _client_id = manager.build_authorize_params(provider, redirect_uri)

            # Store PKCE state — in production use session store
            if auth.session_store is not None:
                session_id = request.cookies.get(auth.config.session_cookie_name, secrets.token_urlsafe(16))
                await auth.session_store.create(
                    f"oauth:{session_id}",
                    "oauth",
                    data={"state": state, "code_verifier": code_verifier},
                    ttl=600,
                )

            url = await manager.authorize_redirect_url(provider, redirect_uri, state, code_verifier)
            return {"authorize_url": url, "state": state}

        @router.get("/oauth/{provider}/callback")
        async def oauth_callback(
            provider: str, code: str, state: str, request: Request, response: Response
        ) -> dict[str, Any]:
            redirect_uri = str(request.url_for("oauth_callback", provider=provider))

            # Retrieve PKCE verifier from session store
            code_verifier = ""
            if auth.session_store is not None:
                session_id = request.cookies.get(auth.config.session_cookie_name, "")
                oauth_data = await auth.session_store.get(f"oauth:{session_id}")
                if oauth_data and oauth_data.get("state") == state:
                    code_verifier = oauth_data.get("code_verifier", "")
                    await auth.session_store.delete(f"oauth:{session_id}")

            user_info = await manager.exchange_code(provider, code, redirect_uri, code_verifier)
            user = await maybe_await(auth.get_or_create_oauth_user(user_info))
            if user is None:
                raise UnauthorizedError("No account linked to this OAuth identity")
            return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=mfa)

    # ── Magic link login ─────────────────────────────────────────

    def _add_magic_link_routes(self, router: APIRouter, config: MagicLinkLogin) -> None:
        auth = self._auth
        strategy = self._pipeline.strategy
        transport = self._transport
        mfa = self._pipeline.mfa

        @router.post("/magic-link/send", status_code=202)
        async def send_magic_link(body: _MagicLinkRequest) -> dict[str, str]:
            user = await maybe_await(auth.get_user_by_identifier(body.email))
            if user is not None:
                token = secrets.token_urlsafe(32)
                link = f"/auth/magic-link/verify?token={token}"
                await maybe_await(auth.send_magic_link(body.email, token, link))
            # Always return success to prevent email enumeration
            return {"detail": "If the email exists, a magic link has been sent."}

        @router.post("/magic-link/verify")
        async def verify_magic_link(body: _MagicLinkVerify, request: Request, response: Response) -> dict[str, Any]:
            user = await maybe_await(auth.verify_magic_link_token(body.token))
            if user is None:
                raise UnauthorizedError("Invalid or expired magic link")
            return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=mfa)

    # ── OTP login ────────────────────────────────────────────────

    def _add_otp_routes(self, router: APIRouter, config: OTPLogin) -> None:
        auth = self._auth
        strategy = self._pipeline.strategy
        transport = self._transport
        mfa = self._pipeline.mfa

        @router.post("/otp/verify")
        async def verify_otp(body: _OTPVerifyRequest, request: Request, response: Response) -> dict[str, Any]:
            user = await maybe_await(auth.get_user_by_identifier(body.username))
            if user is None:
                raise UnauthorizedError("Invalid credentials")
            valid = await maybe_await(auth.verify_otp(user, body.code))
            if not valid:
                raise UnauthorizedError("Invalid OTP code")
            return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=mfa)

    # ── Passkey login ────────────────────────────────────────────

    def _add_passkey_routes(self, router: APIRouter, config: PasskeyLogin) -> None:
        auth = self._auth
        strategy = self._pipeline.strategy
        transport = self._transport
        mfa = self._pipeline.mfa

        @router.post("/passkey/login/begin")
        async def passkey_login_begin(request: Request) -> dict[str, Any]:
            challenge = await maybe_await(auth.create_passkey_challenge())
            return challenge

        @router.post("/passkey/login/complete")
        async def passkey_login_complete(
            body: _PasskeyCredential, request: Request, response: Response
        ) -> dict[str, Any]:
            user = await maybe_await(auth.verify_passkey_assertion({}, body.credential))
            if user is None:
                raise UnauthorizedError("Passkey verification failed")
            return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=mfa)

        # Authenticated passkey management routes
        _bearer = HTTPBearer(auto_error=False)

        @router.post("/passkey/register/begin")
        async def passkey_register_begin(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, Any]:
            ctx = await self._resolve_context(request)
            challenge = await maybe_await(auth.create_passkey_challenge(ctx.user))
            return challenge

        @router.post("/passkey/register/complete")
        async def passkey_register_complete(
            body: _PasskeyCredential,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, str]:
            ctx = await self._resolve_context(request)
            await maybe_await(auth.verify_passkey_registration(ctx.user, body.credential))
            return {"detail": "Passkey registered"}

        @router.get("/passkey/list")
        async def passkey_list(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> list[dict[str, Any]]:
            ctx = await self._resolve_context(request)
            return await maybe_await(auth.get_user_passkeys(ctx.user))

        @router.delete("/passkey/{credential_id}")
        async def passkey_delete(
            credential_id: str,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, str]:
            ctx = await self._resolve_context(request)
            await maybe_await(auth.delete_passkey(ctx.user, credential_id))
            return {"detail": "Passkey deleted"}

    # ── MFA routes ───────────────────────────────────────────────

    def _add_mfa_routes(self, router: APIRouter, mfa_config: MFA) -> None:
        auth = self._auth
        strategy = self._pipeline.strategy
        transport = self._transport

        @router.post("/mfa/challenge")
        async def mfa_challenge(request: Request) -> dict[str, Any]:
            """Request an MFA challenge (e.g. send OTP, get passkey challenge)."""
            # mfa_token in body or header
            return {"detail": "MFA challenge issued", "methods": mfa_config.methods}

        @router.post("/mfa/verify")
        async def mfa_verify(body: _MFAVerifyRequest, request: Request, response: Response) -> dict[str, Any]:
            """Verify MFA code and issue full credentials."""
            try:
                claims = auth.token_service.decode_token(body.mfa_token)
            except Exception as exc:
                raise UnauthorizedError("Invalid MFA token") from exc

            if not claims.get("mfa_pending"):
                raise UnauthorizedError("Invalid MFA token")

            user_id = claims.get("sub")
            user = await maybe_await(auth.get_user(user_id))
            if user is None:
                raise UnauthorizedError("User not found")

            valid = await maybe_await(auth.verify_mfa(user, body.method, body.code))
            if not valid:
                raise ForbiddenError("Invalid MFA code")

            # MFA passed — issue full credentials (no MFA check again)
            return await _issue_credentials(auth, user, strategy, transport, request, response, mfa=None)

        _bearer = HTTPBearer(auto_error=False)

        @router.post("/mfa/enroll")
        async def mfa_enroll(
            body: _MFAEnrollRequest,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, Any]:
            """Enroll a new MFA method (returns setup data like TOTP secret/QR)."""
            ctx = await self._resolve_context(request)
            if body.method not in mfa_config.methods:
                raise ForbiddenError(f"MFA method '{body.method}' is not enabled")
            return await maybe_await(auth.enroll_mfa(ctx.user, body.method))

        @router.get("/mfa/methods")
        async def mfa_methods(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, Any]:
            """List enrolled MFA methods for the current user."""
            ctx = await self._resolve_context(request)
            enrolled = await maybe_await(auth.get_mfa_methods(ctx.user))
            return {"enrolled": enrolled, "available": mfa_config.methods}

    # ── Password reset (3-step) ──────────────────────────────────

    def _add_password_reset_routes(self, router: APIRouter, config: PasswordReset) -> None:
        auth = self._auth

        @router.post("/password/forgot", status_code=202)
        async def forgot_password(body: _ForgotPasswordRequest) -> dict[str, str]:
            user = await maybe_await(auth.get_user_by_identifier(body.email))
            if user is not None:
                token = await maybe_await(auth.create_reset_token(user))
                link = f"/auth/password/reset/confirm?token={token}"
                await maybe_await(auth.send_reset_email(body.email, token, link))
            # Always return success to prevent email enumeration
            return {"detail": "If the email exists, a reset link has been sent."}

        @router.post("/password/reset/confirm")
        async def reset_confirm(body: _ResetConfirmRequest) -> dict[str, str]:
            """Validate reset token and invalidate old password.

            After this step the user **cannot** log in with the old
            password and must complete the reset.
            """
            user = await maybe_await(auth.validate_reset_token(body.token))
            if user is None:
                raise UnauthorizedError("Invalid or expired reset token")

            # Invalidate old password — user must finish the reset
            await maybe_await(auth.invalidate_password(user))

            # Issue a short-lived reset session token
            reset_session = auth.token_service.create_access_token(
                str(user.id),
                extra_claims={"type": "reset_session"},
                fresh=True,
            )
            return {"reset_session": reset_session}

        @router.post("/password/reset/complete")
        async def reset_complete(body: _ResetCompleteRequest) -> dict[str, str]:
            """Set new password using the reset session from confirm step."""
            try:
                claims = auth.token_service.decode_token(body.reset_session)
            except Exception as exc:
                raise UnauthorizedError("Invalid or expired reset session") from exc

            if claims.get("type") != "reset_session":
                raise UnauthorizedError("Invalid reset session")

            user_id = claims.get("sub")
            user = await maybe_await(auth.get_user(user_id))
            if user is None:
                raise UnauthorizedError("User not found")

            await maybe_await(auth.set_password(user, body.new_password))
            return {"detail": "Password has been reset successfully."}

    # ── Account linking ──────────────────────────────────────────

    def _add_account_linking_routes(self, router: APIRouter) -> None:
        auth = self._auth
        _bearer = HTTPBearer(auto_error=False)

        # OAuth linking uses the same OAuthManager if oauth is configured
        oauth_config = self._pipeline.oauth
        manager = None
        if oauth_config is not None:
            manager = OAuthManager()
            for provider in oauth_config.providers:
                kwargs: dict[str, Any] = {}
                if provider.scopes:
                    kwargs["client_kwargs"] = {"scope": " ".join(provider.scopes)}
                kwargs.update(provider.extra)
                manager.register(
                    provider.name,
                    client_id=provider.client_id,
                    client_secret=provider.client_secret,
                    **kwargs,
                )

        if manager is not None:

            @router.post("/account/link/oauth/{provider}")
            async def link_oauth_provider(
                provider: str,
                request: Request,
                _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
            ) -> dict[str, Any]:
                """Initiate OAuth linking for the current user."""
                ctx = await self._resolve_context(request)
                redirect_uri = str(request.url_for("link_oauth_callback", provider=provider))
                state, code_verifier, _client_id = manager.build_authorize_params(provider, redirect_uri)  # type: ignore[union-attr]

                if auth.session_store is not None:
                    session_id = secrets.token_urlsafe(16)
                    await auth.session_store.create(
                        f"link:{session_id}",
                        str(ctx.user.id),
                        data={"state": state, "code_verifier": code_verifier, "user_id": str(ctx.user.id)},
                        ttl=600,
                    )

                url = await manager.authorize_redirect_url(provider, redirect_uri, state, code_verifier)  # type: ignore[union-attr]
                return {"authorize_url": url, "state": state}

            @router.get("/account/link/oauth/{provider}/callback")
            async def link_oauth_callback(
                provider: str,
                code: str,
                state: str,
                request: Request,
                _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
            ) -> dict[str, str]:
                """Complete OAuth linking after provider redirect."""
                ctx = await self._resolve_context(request)
                redirect_uri = str(request.url_for("link_oauth_callback", provider=provider))
                user_info = await manager.exchange_code(provider, code, redirect_uri, "")  # type: ignore[union-attr]
                await maybe_await(auth.link_oauth(ctx.user, user_info))
                return {"detail": f"{provider} account linked"}

            @router.delete("/account/link/oauth/{provider}")
            async def unlink_oauth_provider(
                provider: str,
                request: Request,
                _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
            ) -> dict[str, str]:
                ctx = await self._resolve_context(request)
                await maybe_await(auth.unlink_oauth(ctx.user, provider))
                return {"detail": f"{provider} account unlinked"}

        @router.post("/account/link/phone")
        async def link_phone(
            body: _LinkPhoneRequest,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, str]:
            ctx = await self._resolve_context(request)
            await maybe_await(auth.link_phone(ctx.user, body.phone))
            return {"detail": "Phone number linked"}

        @router.post("/account/link/email")
        async def link_email(
            body: _LinkEmailRequest,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> dict[str, str]:
            ctx = await self._resolve_context(request)
            await maybe_await(auth.link_email(ctx.user, body.email))
            return {"detail": "Email address linked"}

        @router.get("/account/links")
        async def get_links(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> list[dict[str, Any]]:
            ctx = await self._resolve_context(request)
            return await maybe_await(auth.get_linked_accounts(ctx.user))

    # ── JWT lifecycle (refresh, logout) ──────────────────────────

    def _add_jwt_lifecycle_routes(self, router: APIRouter, strategy: JWTStrategy) -> None:
        auth = self._auth
        transport = self._transport
        _bearer = HTTPBearer(auto_error=False)

        if strategy.refresh:
            refresh_service = RefreshService(auth.token_service, auth.token_store, auth.config)

            @router.post("/refresh")
            async def refresh(body: _RefreshRequest, response: Response) -> dict[str, str]:
                pair = await refresh_service.rotate(body.refresh_token)
                transport.set_token(response, pair.access_token)
                return {
                    "access_token": pair.access_token,
                    "refresh_token": pair.refresh_token,
                    "token_type": "bearer",
                }

        @router.post("/logout", status_code=204)
        async def jwt_logout(
            request: Request,
            response: Response,
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        ) -> None:
            raw = transport.extract_token(request)
            if raw and strategy.revocable:
                try:
                    claims = auth.token_service.decode_token(raw)
                    family_id = await auth.token_store.get_family_id(claims["jti"])
                    if family_id:
                        await auth.token_store.revoke_family(family_id)
                    else:
                        await auth.token_store.revoke(claims["jti"], claims["exp"])
                except Exception:
                    pass
            transport.delete_token(response)

        if strategy.revocable:

            @router.post("/logout-all", status_code=204)
            async def jwt_logout_all(
                request: Request,
                response: Response,
                _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
            ) -> None:
                raw = transport.extract_token(request)
                if raw:
                    try:
                        claims = auth.token_service.decode_token(raw)
                        await auth.token_store.revoke_all_for_user(claims["sub"])
                    except Exception:
                        pass
                transport.delete_token(response)

    # ── Session lifecycle ────────────────────────────────────────

    def _add_session_lifecycle_routes(self, router: APIRouter, strategy: SessionStrategy) -> None:
        auth = self._auth

        @router.post("/logout", status_code=204)
        async def session_logout(request: Request, response: Response) -> None:
            session_id = request.cookies.get(strategy.cookie_name)
            if session_id and auth.session_store:
                await auth.session_store.delete(session_id)
            response.delete_cookie(strategy.cookie_name)

    # ── Helper ───────────────────────────────────────────────────

    async def _resolve_context(self, request: Request) -> AuthContext:
        """Resolve auth context for authenticated routes within the pipeline router."""
        if self._resolver is not None:
            ctx = await self._resolver.resolve(request, optional=False)
        else:
            # Fallback for JWT-based pipelines
            raw_token = self._transport.extract_token(request)
            ctx = await self._auth.build_context(raw_token, optional=False, request=request)
        if not ctx.is_authenticated():
            raise UnauthorizedError()
        return ctx
