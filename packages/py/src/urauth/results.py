"""Framework-agnostic result types returned by Auth endpoint methods."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Successful authentication — contains issued tokens."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    family_id: str = ""


@dataclass(frozen=True, slots=True)
class MFARequiredResult:
    """Login succeeded but MFA verification is pending."""

    mfa_token: str
    methods: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ResetSessionResult:
    """Password reset token confirmed — use reset_session to set new password."""

    reset_session: str


@dataclass(frozen=True, slots=True)
class MessageResult:
    """Generic success message (e.g. "OTP sent", "password reset email sent")."""

    detail: str


LoginResult = AuthResult | MFARequiredResult
