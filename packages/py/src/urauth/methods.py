"""Auth method and login configuration models.

Replaces the old ``Pipeline`` module. All models are Pydantic BaseModel
subclasses for validation and serialization.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from urauth.storage.base import SessionStore, TokenStore

# ── Auth Methods (was Strategies) ───────────────────────────────


class JWT(BaseModel):
    """Stateless JWT auth method.

    Includes token TTLs and store — everything needed
    for JWT-based authentication lives here.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    kind: Literal["jwt"] = "jwt"
    ttl: int = 900
    """Access token TTL in seconds (default: 15 minutes)."""
    refresh_ttl: int = 604800
    """Refresh token TTL in seconds (default: 7 days)."""
    refresh: bool = True
    """Enable refresh token rotation."""
    revocable: bool = True
    """Check token blocklist on each request."""
    transport: Literal["bearer", "cookie", "hybrid"] = "bearer"
    """How tokens are sent — ``"bearer"`` header, ``"cookie"``, or ``"hybrid"``."""
    store: TokenStore | None = None
    """Token store for revocation tracking. Uses in-memory store if None."""
    issuer: str | None = None
    """JWT ``iss`` claim."""
    audience: str | None = None
    """JWT ``aud`` claim."""


class Session(BaseModel):
    """Server-side session auth method.

    Session ID stored in an HTTP-only cookie, session data in a
    :class:`~urauth.backends.base.SessionStore`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    kind: Literal["session"] = "session"
    cookie_name: str = "session_id"
    ttl: int = 86400
    """Session TTL in seconds (default: 24 hours)."""
    store: SessionStore | None = None
    """Session store backend. Required for session-based auth."""


class BasicAuth(BaseModel):
    """HTTP Basic auth — re-authenticate every request."""

    kind: Literal["basic"] = "basic"
    realm: str = "Restricted"


class APIKey(BaseModel):
    """API key authentication via header or query parameter."""

    kind: Literal["apikey"] = "apikey"
    header_name: str = "X-API-Key"
    query_param: str | None = None


class Fallback(BaseModel):
    """Try multiple auth methods in order until one succeeds."""

    kind: Literal["fallback"] = "fallback"
    methods: list[JWT | Session | BasicAuth | APIKey] = []


Method = JWT | Session | BasicAuth | APIKey | Fallback


# ── OAuth Providers ─────────────────────────────────────────────


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


# ── Login Methods ───────────────────────────────────────────────


class Password(BaseModel):
    """Password-based login.

    Password reset is automatically available when at least one
    identity in the ``identity`` list has OTP configured (a delivery
    channel). These TTL fields control the reset flow timing.
    """

    reset_token_ttl: int = 3600
    """How long the reset token is valid in seconds (default: 1 hour)."""
    reset_session_ttl: int = 600
    """How long the reset session lasts after confirmation (default: 10 minutes)."""


class OTP(BaseModel):
    """One-time password configuration.

    User provides ``send`` and ``verify`` callables, making it
    easy to plug in any email/phone/SMS provider::

        otp_phone = OTP(
            send=send_sms,       # async (user, code) -> None
            verify=verify_code,  # async (user, code) -> bool
            ttl=300,
            revoke_previous=True,
        )
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    send: Callable[..., Any]
    """Callable to send the OTP code: ``(user, code) -> None``."""
    verify: Callable[..., Any]
    """Callable to verify the OTP code: ``(user, code) -> bool``."""
    digits: int = 6
    """Length of the OTP code."""
    code_type: Literal["numeric", "alpha", "alphanumeric"] = "numeric"
    """Character set for generated codes."""
    ttl: int = 300
    """How long the OTP code is valid in seconds (default: 5 minutes)."""
    revoke_previous: bool = True
    """If True, sending a new code invalidates all previous codes."""


class ResetablePassword(Password):
    """Deprecated: use ``Password`` with identity-driven OTP channels instead.

    Kept for backward compatibility. Prefer::

        Auth(
            identity=Email(otp=OTP(send=..., verify=...)),
            password=Password(),
        )
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    verification: OTP | dict[str, OTP] | None = None
    """Deprecated: OTP verification now lives on Email/Phone identity."""


class OAuth(BaseModel):
    """OAuth/social login configuration."""

    providers: list[OAuthProvider] = []
    callback_path: str = "/auth/oauth/{provider}/callback"


class MagicLink(BaseModel):
    """Email magic link login."""

    token_ttl: int = 600
    """Token validity in seconds (default: 10 minutes)."""


class TOTP(BaseModel):
    """Time-based OTP (built-in, works out of the box).

    Unlike :class:`OTP`, TOTP uses a standard algorithm
    and doesn't require user-provided send/verify functions.
    """

    issuer: str = "MyApp"
    """Shown in authenticator apps."""
    digits: int = 6
    period: int = 30
    """Time step in seconds."""
    algorithm: str = "SHA1"


class Passkey(BaseModel):
    """WebAuthn/FIDO2 passkey authentication."""

    rp_name: str = "MyApp"
    """Relying party display name."""
    rp_id: str | None = None
    """Relying party ID (defaults to request host)."""


class MFA(BaseModel):
    """Multi-factor authentication configuration."""

    methods: list[Literal["otp", "totp", "passkey"]]
    """Enabled MFA method types."""
    required: bool = False
    """If True, all users must complete MFA."""
    grace_period: int = 0
    """Seconds after fresh login before MFA is required again."""


class AccountLinking(BaseModel):
    """Account linking — connect/disconnect OAuth, phone, email."""

    pass


class Identifiers(BaseModel):
    """Deprecated: use ``identity=`` parameter with ``Username``, ``Email``, ``Phone`` instead.

    Kept for backward compatibility.
    """

    email: bool = True
    phone: bool = False
    username: bool = False


# ── Identity Types ─────────────────────────────────────────────


class Username(BaseModel):
    """Login via username. No delivery channel.

    Cannot send OTP codes, magic links, or password reset emails.
    Use ``Email`` or ``Phone`` for features that require delivery.

    ``Username`` intentionally has no ``otp`` or ``magic_link`` fields —
    attempting ``Username(otp=...)`` is a TypeError.
    """

    pass


class Email(BaseModel):
    """Login via email. Can deliver OTP codes and magic links.

    Attach an :class:`OTP` instance to enable email-based OTP
    verification (for login, password reset, MFA)::

        Email(
            otp=OTP(send=send_email_code, verify=verify_code),
            magic_link=MagicLink(token_ttl=600),
        )
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    otp: OTP | None = None
    """OTP delivery via email. Enables OTP login and password reset."""
    magic_link: MagicLink | None = None
    """Magic link delivery via email."""


class Phone(BaseModel):
    """Login via phone number. Can deliver OTP codes via SMS.

    Attach an :class:`OTP` instance to enable phone-based OTP
    verification::

        Phone(otp=OTP(send=send_sms, verify=verify_sms_code))
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    otp: OTP | None = None
    """OTP delivery via SMS/phone. Enables OTP login and password reset."""


Identity = Username | Email | Phone
"""Union of all identity types that can appear in ``Auth(identity=...)``."""

DeliveryChannel = Email | Phone
"""Identity types that can send OTP codes or magic links."""
