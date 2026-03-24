"""Declarative auth pipeline configuration.

Define your entire auth setup in one place::

    pipeline = Pipeline(
        strategy=JWTStrategy(refresh=True, revocable=True),
        password=True,
        oauth=OAuthLogin(providers=[
            Google(client_id="...", client_secret="..."),
            GitHub(client_id="...", client_secret="..."),
        ]),
        mfa=MFA(methods=["otp", "passkey"]),
        password_reset=True,
        account_linking=True,
        identifiers=Identifiers(email=True, phone=True),
    )
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

# ── Auth Strategies ──────────────────────────────────────────────


class JWTStrategy(BaseModel):
    """Stateless JWT auth strategy.

    Args:
        refresh: Enable refresh token rotation.
        revocable: Check token blocklist on each request.
        transport: How tokens are sent — ``"bearer"`` header,
            ``"cookie"``, or ``"hybrid"`` (try bearer then cookie).
    """

    kind: Literal["jwt"] = "jwt"
    refresh: bool = True
    revocable: bool = True
    transport: Literal["bearer", "cookie", "hybrid"] = "bearer"


class SessionStrategy(BaseModel):
    """Server-side session strategy.

    Session ID stored in an HTTP-only cookie, session data in a
    :class:`~urauth.backends.base.SessionStore`.
    """

    kind: Literal["session"] = "session"
    cookie_name: str = "session_id"


class BasicAuthStrategy(BaseModel):
    """HTTP Basic auth — re-authenticate every request."""

    kind: Literal["basic"] = "basic"
    realm: str = "Restricted"


class APIKeyStrategy(BaseModel):
    """API key authentication via header or query parameter."""

    kind: Literal["apikey"] = "apikey"
    header_name: str = "X-API-Key"
    query_param: str | None = None


class FallbackStrategy(BaseModel):
    """Try multiple strategies in order until one succeeds."""

    kind: Literal["fallback"] = "fallback"
    strategies: list[JWTStrategy | SessionStrategy | BasicAuthStrategy | APIKeyStrategy] = []


Strategy = JWTStrategy | SessionStrategy | BasicAuthStrategy | APIKeyStrategy | FallbackStrategy


# ── OAuth Providers ──────────────────────────────────────────────


class OAuthProvider(BaseModel):
    """Base OAuth provider configuration."""

    name: str
    client_id: str
    client_secret: str
    scopes: list[str] | None = None
    extra: dict[str, Any] = {}


class Google(OAuthProvider):
    name: str = "google"


class GitHub(OAuthProvider):
    name: str = "github"


class Microsoft(OAuthProvider):
    name: str = "microsoft"


class Apple(OAuthProvider):
    name: str = "apple"


class Discord(OAuthProvider):
    name: str = "discord"


class GitLab(OAuthProvider):
    name: str = "gitlab"


# ── Login Methods ────────────────────────────────────────────────


class PasswordLogin(BaseModel):
    """Username/password login method."""

    kind: Literal["password"] = "password"
    enabled: bool = True


class OAuthLogin(BaseModel):
    """OAuth/social login method."""

    kind: Literal["oauth"] = "oauth"
    providers: list[OAuthProvider] = []
    callback_path: str = "/auth/oauth/{provider}/callback"


class MagicLinkLogin(BaseModel):
    """Email magic link login."""

    kind: Literal["magic_link"] = "magic_link"
    token_ttl: int = 600  # 10 minutes


class OTPLogin(BaseModel):
    """OTP (one-time password) login.

    Args:
        code_type: Character set — ``"numeric"`` (0-9),
            ``"alpha"`` (A-Z), or ``"alphanumeric"`` (both).
        digits: Length of the OTP code.
        period: Validity window in seconds.
        issuer_name: Shown in authenticator apps.
    """

    kind: Literal["otp"] = "otp"
    code_type: Literal["numeric", "alpha", "alphanumeric"] = "numeric"
    digits: int = 6
    period: int = 30
    issuer_name: str = "MyApp"


class PasskeyLogin(BaseModel):
    """WebAuthn/FIDO2 passkey authentication."""

    kind: Literal["passkey"] = "passkey"
    rp_name: str = "MyApp"
    rp_id: str | None = None  # defaults to request host


LoginMethod = PasswordLogin | OAuthLogin | MagicLinkLogin | OTPLogin | PasskeyLogin


# ── MFA ──────────────────────────────────────────────────────────


class MFA(BaseModel):
    """Multi-factor authentication configuration.

    Args:
        methods: Allowed MFA methods (``"otp"``, ``"passkey"``).
        required: If ``True``, all users must complete MFA.
            If ``False``, only enrolled users are prompted.
        grace_period: Seconds after fresh login before MFA is
            required again.
    """

    methods: list[Literal["otp", "passkey"]] = ["otp"]
    required: bool = False
    grace_period: int = 0


# ── Account Features ─────────────────────────────────────────────


class PasswordReset(BaseModel):
    """Password reset configuration (3-step flow).

    Flow:
        1. ``POST /password/forgot`` — sends reset email.
        2. ``POST /password/reset/confirm`` — validates token,
           **invalidates old password** immediately.
        3. ``POST /password/reset/complete`` — sets new password
           using the ``reset_session`` from step 2.

    Args:
        token_ttl: How long the reset token is valid (seconds).
        reset_session_ttl: How long the reset session lasts after
            token confirmation (seconds).
    """

    token_ttl: int = 3600
    reset_session_ttl: int = 600


class AccountLinking(BaseModel):
    """Account linking — connect/disconnect OAuth, phone, email."""

    pass


class Identifiers(BaseModel):
    """Which identifiers users can log in with.

    When multiple are enabled, ``POST /login`` accepts an
    ``identifier`` field and resolves via
    :meth:`~urauth.auth.Auth.get_user_by_identifier`.
    """

    email: bool = True
    phone: bool = False
    username: bool = False


# ── Pipeline ─────────────────────────────────────────────────────


class Pipeline(BaseModel):
    """Declarative auth pipeline — single source of truth.

    Configure once on :class:`~urauth.auth.Auth`, and
    :meth:`~urauth.fastapi.auth.FastAuth.auto_router` generates
    all routes automatically.
    """

    # Strategy — how authenticated state is maintained per-request
    strategy: Strategy = JWTStrategy()

    # Login methods — how users initially prove identity
    password: bool | PasswordLogin = False
    oauth: OAuthLogin | None = None
    magic_link: MagicLinkLogin | None = None
    otp: OTPLogin | None = None
    passkey: bool | PasskeyLogin = False

    # MFA — second factor after primary login
    mfa: MFA | None = None

    # Account features
    password_reset: bool | PasswordReset = False
    account_linking: bool | AccountLinking = False
    identifiers: Identifiers = Identifiers()

    def enabled_methods(self) -> list[LoginMethod]:
        """Return list of enabled login methods."""
        methods: list[LoginMethod] = []
        if self.password is True:
            methods.append(PasswordLogin())
        elif isinstance(self.password, PasswordLogin) and self.password.enabled:
            methods.append(self.password)
        if self.oauth is not None:
            methods.append(self.oauth)
        if self.magic_link is not None:
            methods.append(self.magic_link)
        if self.otp is not None:
            methods.append(self.otp)
        if self.passkey is True:
            methods.append(PasskeyLogin())
        elif isinstance(self.passkey, PasskeyLogin):
            methods.append(self.passkey)
        return methods

    @property
    def has_password_reset(self) -> bool:
        return self.password_reset is True or isinstance(self.password_reset, PasswordReset)

    @property
    def password_reset_config(self) -> PasswordReset:
        if isinstance(self.password_reset, PasswordReset):
            return self.password_reset
        return PasswordReset()

    @property
    def has_account_linking(self) -> bool:
        return self.account_linking is True or isinstance(self.account_linking, AccountLinking)

    @property
    def has_mfa(self) -> bool:
        return self.mfa is not None
