# pyright: reportUnusedFunction=false, reportUnusedClass=false
"""Auto-generate FastAPI routes from Auth configuration.

The :class:`RouterBuilder` inspects the :class:`~urauth.auth.Auth`
instance and creates thin endpoint handlers that delegate to
``Auth`` methods.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from urauth.auth import Auth, maybe_await
from urauth.context import AuthContext
from urauth.exceptions import UnauthorizedError
from urauth.fastapi.transport.base import Transport
from urauth.fastapi.transport.cookie import RefreshCookieManager
from urauth.methods import (
    JWT,
    Email,
    Fallback,
    OAuth,
    Session,
    Username,
)
from urauth.results import AuthResult, MFARequiredResult, ResetSessionResult

# ── Shared request / response schemas ────────────────────────────

_BEARER_SCHEME = Depends(HTTPBearer(auto_error=False))


class _IdentifierLoginRequest(BaseModel):
    identifier: str
    password: str


class _UsernameLoginRequest(BaseModel):
    username: str
    password: str


class _EmailLoginRequest(BaseModel):
    email: str
    password: str


class _PhoneLoginRequest(BaseModel):
    phone: str
    password: str


class _TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class _RefreshRequest(BaseModel):
    refresh_token: str | None = None


class _MagicLinkRequest(BaseModel):
    email: str


class _MagicLinkVerify(BaseModel):
    token: str


class _OTPSendRequest(BaseModel):
    identifier: str
    channel: str | None = None


class _OTPVerifyRequest(BaseModel):
    identifier: str
    code: str
    channel: str | None = None


class _MFAVerifyRequest(BaseModel):
    mfa_token: str
    method: str
    code: str


class _MFAEnrollRequest(BaseModel):
    method: str


class _ForgotPasswordRequest(BaseModel):
    identifier: str
    channel: str | None = None


class _ResetConfirmRequest(BaseModel):
    token: str
    channel: str | None = None
    verification_method: str | None = None


class _ResetVerifyRequest(BaseModel):
    pending_token: str
    code: str
    channel: str | None = None
    verification_method: str | None = None


class _ResetCompleteRequest(BaseModel):
    reset_session: str
    new_password: str


class _LinkPhoneRequest(BaseModel):
    phone: str


class _LinkEmailRequest(BaseModel):
    email: str


class _PasskeyCredential(BaseModel):
    credential: dict[str, Any]


# ── Helpers ──────────────────────────────────────────────────────


def _result_to_dict(result: AuthResult | MFARequiredResult) -> dict[str, Any]:
    """Convert a login result to a JSON-serializable dict.

    The refresh token is intentionally excluded — it is delivered via an
    httpOnly cookie set by ``_set_refresh_cookie``, not in the response body.
    """
    if isinstance(result, MFARequiredResult):
        return {"mfa_token": result.mfa_token, "mfa_required": True, "methods": result.methods}
    return {
        "access_token": result.access_token,
        "token_type": result.token_type,
    }


def _set_transport_token(transport: Transport, response: Response, result: AuthResult) -> None:
    """Set access token on response via transport."""
    transport.set_token(response, result.access_token)


def _set_refresh_cookie(refresh_mgr: RefreshCookieManager, response: Response, result: AuthResult) -> None:
    """Set refresh token as httpOnly cookie on response."""
    refresh_mgr.set_token(response, result.refresh_token)


# ── Router builder ───────────────────────────────────────────────


class RouterBuilder:
    """Builds a complete FastAPI router from Auth configuration.

    Each endpoint is a thin handler that:
    1. Parses the request body
    2. Calls the corresponding Auth method
    3. Applies transport side-effects (set cookies/headers)
    4. Returns the serialized result
    """

    def __init__(self, auth: Auth, transport: Transport) -> None:
        self._auth = auth
        self._transport = transport
        self._refresh_mgr = RefreshCookieManager(auth.internal_config)

    def build(self) -> APIRouter:
        """Build the combined router with all enabled endpoints.

        Smart route generation based on identity configuration:
        - Password reset routes only when OTP delivery channels exist
        - OTP routes only when any identity has OTP configured
        - Magic link routes only when Email has magic_link configured
        - Login schema adapts to single vs multiple identity types
        """
        router = APIRouter(prefix=self._auth.auth_prefix, tags=["auth"])

        # Password login routes
        if self._auth.password is not None:
            self._add_password_routes(router)

        # OAuth routes
        if self._auth.oauth is not None:
            self._add_oauth_routes(router, self._auth.oauth)

        # Magic link routes — only when Email identity has magic_link
        if self._auth.magic_link_email is not None:
            self._add_magic_link_routes(router)

        # OTP routes — only when any identity has OTP configured
        if self._auth.otp_channels:
            self._add_otp_routes(router)

        # Passkey routes
        if self._auth.passkey is not None:
            self._add_passkey_routes(router)

        # MFA routes
        if self._auth.mfa is not None:
            self._add_mfa_routes(router)

        # Password reset routes — only when password + OTP delivery channel exists
        if self._auth.has_password_reset:
            self._add_password_reset_routes(router)

        # Account linking routes
        if self._auth.account_linking is not None:
            self._add_account_linking_routes(router)

        # Lifecycle routes (refresh, logout) — always present for JWT/Session
        self._add_lifecycle_routes(router)

        return router

    # ── Password login ───────────────────────────────────────────

    def _add_password_routes(self, router: APIRouter) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr
        identity = auth.identity

        # Determine login schema based on identity configuration
        # Single identity → typed field name; multiple → generic identifier
        if len(identity) == 1:
            single = identity[0]
            if isinstance(single, Username):
                @router.post("/login")
                async def login_username(
                    body: _UsernameLoginRequest, request: Request, response: Response
                ) -> dict[str, Any]:
                    result = await auth.login(body.username, body.password)
                    if isinstance(result, AuthResult):
                        _set_transport_token(transport, response, result)
                        _set_refresh_cookie(refresh_mgr, response, result)
                    return _result_to_dict(result)
            elif isinstance(single, Email):
                @router.post("/login")
                async def login_email(
                    body: _EmailLoginRequest, request: Request, response: Response
                ) -> dict[str, Any]:
                    result = await auth.login(body.email, body.password)
                    if isinstance(result, AuthResult):
                        _set_transport_token(transport, response, result)
                        _set_refresh_cookie(refresh_mgr, response, result)
                    return _result_to_dict(result)
            else:  # Phone
                @router.post("/login")
                async def login_phone(
                    body: _PhoneLoginRequest, request: Request, response: Response
                ) -> dict[str, Any]:
                    result = await auth.login(body.phone, body.password)
                    if isinstance(result, AuthResult):
                        _set_transport_token(transport, response, result)
                        _set_refresh_cookie(refresh_mgr, response, result)
                    return _result_to_dict(result)
        else:
            @router.post("/login")
            async def login_identifier(
                body: _IdentifierLoginRequest, request: Request, response: Response
            ) -> dict[str, Any]:
                result = await auth.login(body.identifier, body.password)
                if isinstance(result, AuthResult):
                    _set_transport_token(transport, response, result)
                    _set_refresh_cookie(refresh_mgr, response, result)
                return _result_to_dict(result)

    # ── OAuth routes ─────────────────────────────────────────────

    def _add_oauth_routes(self, router: APIRouter, oauth_config: OAuth) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr

        @router.get("/oauth/{provider}/authorize")
        async def oauth_authorize(provider: str, request: Request) -> dict[str, Any]:
            import secrets as _secrets

            from urauth.oauth2.client import OAuthManager

            provider_cfg = next((p for p in oauth_config.providers if p.name == provider), None)
            if provider_cfg is None:
                raise UnauthorizedError(f"Unknown OAuth provider: {provider}")

            manager = OAuthManager()
            manager.register(
                provider_cfg.name,
                client_id=provider_cfg.client_id,
                client_secret=provider_cfg.client_secret,
                client_kwargs={"scope": " ".join(provider_cfg.scopes or ["openid", "email", "profile"])},
            )
            state = _secrets.token_urlsafe(32)
            code_verifier = _secrets.token_urlsafe(43)
            callback = str(request.url_for("oauth_callback", provider=provider))
            url: str = await manager.authorize_redirect_url(provider_cfg.name, callback, state, code_verifier)
            return {"authorization_url": url, "state": state, "code_verifier": code_verifier}

        @router.get("/oauth/{provider}/callback")
        async def oauth_callback(
            provider: str, code: str, state: str, request: Request, response: Response,
            code_verifier: str = "",
        ) -> dict[str, Any]:
            from urauth.oauth2.client import OAuthManager

            provider_cfg = next((p for p in oauth_config.providers if p.name == provider), None)
            if provider_cfg is None:
                raise UnauthorizedError(f"Unknown OAuth provider: {provider}")

            manager = OAuthManager()
            manager.register(
                provider_cfg.name,
                client_id=provider_cfg.client_id,
                client_secret=provider_cfg.client_secret,
            )
            callback = str(request.url_for("oauth_callback", provider=provider))
            user_info = await manager.exchange_code(provider_cfg.name, code, callback, code_verifier)
            user = await maybe_await(auth.get_or_create_oauth_user(user_info))
            if user is None:
                raise UnauthorizedError("Could not resolve OAuth user")

            result = await auth.issue_for_user(user)
            if isinstance(result, AuthResult):
                _set_transport_token(transport, response, result)
                _set_refresh_cookie(refresh_mgr, response, result)
            return _result_to_dict(result)

    # ── Magic link routes ────────────────────────────────────────

    def _add_magic_link_routes(self, router: APIRouter) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr

        @router.post("/magic-link/send")
        async def send_magic_link(body: _MagicLinkRequest) -> dict[str, Any]:
            result = await auth.send_magic_link_request(body.email)
            return {"detail": result.detail}

        @router.post("/magic-link/verify")
        async def verify_magic_link(body: _MagicLinkVerify, response: Response) -> dict[str, Any]:
            result = await auth.verify_magic_link(body.token)
            if isinstance(result, AuthResult):
                _set_transport_token(transport, response, result)
                _set_refresh_cookie(refresh_mgr, response, result)
            return _result_to_dict(result)

    # ── OTP routes ───────────────────────────────────────────────

    def _add_otp_routes(self, router: APIRouter) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr

        @router.post("/otp/send")
        async def send_otp(body: _OTPSendRequest) -> dict[str, Any]:
            result = await auth.send_otp_code(body.identifier, channel=body.channel)
            return {"detail": result.detail}

        @router.post("/otp/verify")
        async def verify_otp(body: _OTPVerifyRequest, response: Response) -> dict[str, Any]:
            result = await auth.verify_otp_login(body.identifier, body.code, channel=body.channel)
            if isinstance(result, AuthResult):
                _set_transport_token(transport, response, result)
                _set_refresh_cookie(refresh_mgr, response, result)
            return _result_to_dict(result)

    # ── Passkey routes ───────────────────────────────────────────

    def _add_passkey_routes(self, router: APIRouter) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr

        @router.post("/passkey/login/begin")
        async def passkey_login_begin() -> dict[str, Any]:
            challenge = await maybe_await(auth.create_passkey_challenge())
            return challenge

        @router.post("/passkey/login/complete")
        async def passkey_login_complete(
            body: _PasskeyCredential, response: Response
        ) -> dict[str, Any]:
            challenge: dict[str, Any] = {}  # Would be stored server-side
            user = await maybe_await(auth.verify_passkey_assertion(challenge, body.credential))
            if user is None:
                raise UnauthorizedError("Invalid passkey assertion")
            result = await auth.issue_for_user(user)
            if isinstance(result, AuthResult):
                _set_transport_token(transport, response, result)
                _set_refresh_cookie(refresh_mgr, response, result)
            return _result_to_dict(result)

        @router.post("/passkey/register/begin")
        async def passkey_register_begin(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:

            ctx = await _resolve_context(auth, request, _credentials)
            challenge = await maybe_await(auth.create_passkey_challenge(ctx.user))
            return challenge

        @router.post("/passkey/register/complete")
        async def passkey_register_complete(
            body: _PasskeyCredential,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:
            ctx = await _resolve_context(auth, request, _credentials)
            await maybe_await(auth.verify_passkey_registration(ctx.user, body.credential))
            return {"detail": "Passkey registered"}

        @router.get("/passkey/list")
        async def passkey_list(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> list[dict[str, Any]]:
            ctx = await _resolve_context(auth, request, _credentials)
            return await maybe_await(auth.get_user_passkeys(ctx.user))

        @router.delete("/passkey/{credential_id}")
        async def passkey_delete(
            credential_id: str,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:
            ctx = await _resolve_context(auth, request, _credentials)
            await maybe_await(auth.delete_passkey(ctx.user, credential_id))
            return {"detail": "Passkey deleted"}

    # ── MFA routes ───────────────────────────────────────────────

    def _add_mfa_routes(self, router: APIRouter) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr

        @router.post("/mfa/challenge")
        async def mfa_challenge(body: BaseModel) -> dict[str, Any]:
            # Body should contain mfa_token
            mfa_token = getattr(body, "mfa_token", "")
            return await auth.mfa_challenge(mfa_token)

        @router.post("/mfa/verify")
        async def mfa_verify(body: _MFAVerifyRequest, response: Response) -> dict[str, Any]:
            result = await auth.mfa_verify(body.mfa_token, body.method, body.code)
            _set_transport_token(transport, response, result)
            _set_refresh_cookie(refresh_mgr, response, result)
            return {
                "access_token": result.access_token,
                "token_type": result.token_type,
            }

        @router.post("/mfa/enroll")
        async def mfa_enroll(
            body: _MFAEnrollRequest,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:
            ctx = await _resolve_context(auth, request, _credentials)
            return await auth.mfa_enroll_method(ctx.user, body.method)

        @router.get("/mfa/methods")
        async def mfa_methods(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:
            ctx = await _resolve_context(auth, request, _credentials)
            enrolled = await maybe_await(auth.get_mfa_methods(ctx.user))
            available = auth.mfa.methods if auth.mfa else []
            return {"enrolled": enrolled, "available": available}

    # ── Password reset routes ────────────────────────────────────

    def _add_password_reset_routes(self, router: APIRouter) -> None:
        auth = self._auth

        @router.post("/password/forgot")
        async def forgot_password(body: _ForgotPasswordRequest) -> dict[str, Any]:
            result = await auth.forgot_password(body.identifier, channel=body.channel)
            return {"detail": result.detail}

        @router.post("/password/reset/confirm")
        async def reset_confirm(body: _ResetConfirmRequest) -> dict[str, Any]:
            result = await auth.reset_password_confirm(
                body.token, channel=body.channel, verification_method=body.verification_method
            )
            if isinstance(result, ResetSessionResult):
                return {"reset_session": result.reset_session}
            return {"detail": result.detail}

        @router.post("/password/reset/verify")
        async def reset_verify(body: _ResetVerifyRequest) -> dict[str, Any]:
            result = await auth.reset_password_verify(
                body.pending_token, body.code, channel=body.channel, verification_method=body.verification_method
            )
            return {"reset_session": result.reset_session}

        @router.post("/password/reset/complete")
        async def reset_complete(body: _ResetCompleteRequest) -> dict[str, Any]:
            result = await auth.reset_password_complete(body.reset_session, body.new_password)
            return {"detail": result.detail}

    # ── Account linking routes ───────────────────────────────────

    def _add_account_linking_routes(self, router: APIRouter) -> None:
        auth = self._auth

        @router.post("/account/link/phone")
        async def link_phone(
            body: _LinkPhoneRequest,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:
            ctx = await _resolve_context(auth, request, _credentials)
            await maybe_await(auth.link_phone(ctx.user, body.phone))
            return {"detail": "Phone linked"}

        @router.post("/account/link/email")
        async def link_email(
            body: _LinkEmailRequest,
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> dict[str, Any]:
            ctx = await _resolve_context(auth, request, _credentials)
            await maybe_await(auth.link_email(ctx.user, body.email))
            return {"detail": "Email linked"}

        @router.get("/account/links")
        async def get_links(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> list[dict[str, Any]]:
            ctx = await _resolve_context(auth, request, _credentials)
            return await maybe_await(auth.get_linked_accounts(ctx.user))

    # ── Lifecycle routes (refresh, logout) ───────────────────────

    def _add_lifecycle_routes(self, router: APIRouter) -> None:
        auth = self._auth
        transport = self._transport
        refresh_mgr = self._refresh_mgr
        method = auth.method

        # JWT lifecycle
        if isinstance(method, JWT) or (isinstance(method, Fallback) and any(isinstance(m, JWT) for m in method.methods)):

            @router.post("/refresh")
            async def refresh(
                request: Request,
                response: Response,
                body: _RefreshRequest | None = Body(default=None),
            ) -> dict[str, Any]:
                # Cookie is primary; body is accepted for non-browser clients
                raw_refresh = (body.refresh_token if body else None) or refresh_mgr.extract_token(request)
                if not raw_refresh:
                    raise UnauthorizedError("Refresh token required")
                result = await auth.refresh_tokens(raw_refresh)
                _set_transport_token(transport, response, result)
                _set_refresh_cookie(refresh_mgr, response, result)
                return {
                    "access_token": result.access_token,
                    "token_type": result.token_type,
                }

            @router.post("/logout")
            async def logout(
                request: Request,
                response: Response,
                _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
            ) -> dict[str, Any]:
                raw_token = transport.extract_token(request)
                if raw_token:
                    await auth.logout(raw_token)
                transport.delete_token(response)
                refresh_mgr.delete_token(response)
                return {"detail": "Logged out"}

            @router.post("/logout-all")
            async def logout_all(
                request: Request,
                response: Response,
                _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
            ) -> dict[str, Any]:
                raw_token = transport.extract_token(request)
                if raw_token:
                    await auth.logout_all(raw_token)
                transport.delete_token(response)
                refresh_mgr.delete_token(response)
                return {"detail": "All sessions logged out"}

        # Session lifecycle
        elif isinstance(method, Session):

            @router.post("/logout")
            async def session_logout(request: Request, response: Response) -> dict[str, Any]:
                session_id = request.cookies.get(method.cookie_name)
                if session_id and auth.session_store:
                    await auth.session_store.delete(session_id)
                response.delete_cookie(key=method.cookie_name)
                return {"detail": "Logged out"}


# ── Helper to resolve auth context within routes ─────────────────


async def _resolve_context(
    auth: Auth,
    request: Request,
    _credentials: HTTPAuthorizationCredentials | None,
) -> AuthContext:
    """Resolve auth context from request for authenticated endpoints."""
    cached = getattr(request.state, "_auth_context", None)
    if cached is not None:
        return cached

    from urauth.fastapi.transport.bearer import BearerTransport

    transport = BearerTransport()
    raw_token = transport.extract_token(request)
    ctx = await auth.build_context(raw_token, optional=False, request=request)
    request.state._auth_context = ctx
    return ctx
