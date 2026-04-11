"""TOTP (Time-based One-Time Password) — RFC 6238 via stdlib only.

No pyotp dependency. Uses hmac + hashlib + struct from the standard library.
Compatible with Google Authenticator, Authy, and any RFC 6238 app.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse


class TOTP:
    """RFC 6238 TOTP implementation.

    Args:
        secret: Base32-encoded shared secret (store this per-user, encrypted at rest).
        digits: OTP length (default 6).
        period: Time step in seconds (default 30).
        algorithm: Hash algorithm — ``"sha1"`` (default, widest app support),
                   ``"sha256"``, or ``"sha512"``.
        issuer: App name shown in authenticator apps.
        window: Number of time steps to allow on either side of current
                (default 1 → ±30 s drift).

    Usage::

        totp = TOTP(secret=user.totp_secret, issuer="MyApp")

        # Enrolment — show this URI as a QR code
        uri = totp.provisioning_uri(account_name=user.email)

        # Verification
        if not totp.verify(code_from_user):
            raise InvalidOTP()
    """

    def __init__(
        self,
        secret: str,
        *,
        digits: int = 6,
        period: int = 30,
        algorithm: str = "sha1",
        issuer: str = "urauth",
        window: int = 1,
    ) -> None:
        self._secret = base64.b32decode(secret.upper().replace(" ", ""))
        self._digits = digits
        self._period = period
        self._algorithm = algorithm
        self._issuer = issuer
        self._window = window

    @property
    def b32_secret(self) -> str:
        """The Base32-encoded shared secret (store this per-user, encrypted at rest)."""
        return base64.b32encode(self._secret).decode()

    @property
    def digits(self) -> int:
        """OTP length."""
        return self._digits

    @staticmethod
    def generate_secret(length: int = 20) -> str:
        """Generate a new random Base32 secret for enrolment."""
        return base64.b32encode(os.urandom(length)).decode()

    def _hotp(self, counter: int) -> str:
        """HMAC-based OTP for a given counter value (RFC 4226)."""
        msg = struct.pack(">Q", counter)
        digest = hmac.new(self._secret, msg, self._algorithm).digest()
        offset = digest[-1] & 0x0F
        code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10**self._digits)).zfill(self._digits)

    def _counter(self, at: float | None = None) -> int:
        return int((at or time.time()) // self._period)

    def generate(self, at: float | None = None) -> str:
        """Generate the current TOTP code."""
        return self._hotp(self._counter(at))

    def verify(self, code: str, at: float | None = None) -> bool:
        """Verify *code* against the current window (±``window`` steps)."""
        now = self._counter(at)
        return any(
            hmac.compare_digest(code, self._hotp(now + offset))
            for offset in range(-self._window, self._window + 1)
        )

    def provisioning_uri(self, account_name: str) -> str:
        """Return an ``otpauth://`` URI suitable for QR code display."""
        label = urllib.parse.quote(f"{self._issuer}:{account_name}", safe="")
        params = {
            "secret": base64.b32encode(self._secret).decode(),
            "issuer": self._issuer,
            "algorithm": self._algorithm.upper(),
            "digits": str(self._digits),
            "period": str(self._period),
        }
        query = urllib.parse.urlencode(params)
        return f"otpauth://totp/{label}?{query}"
