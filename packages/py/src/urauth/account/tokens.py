"""Signed token generation and verification for account flows.

Uses itsdangerous TimestampSigner so tokens are:
- Tamper-proof (HMAC-signed with the app secret key)
- Time-limited (built-in expiry, no DB lookup needed)
- Opaque to the caller (base64url encoded)

Typical flows:
- Magic link  → generate() → email link → verify() → log user in
- Password reset → generate() → email link → verify() → allow set_password()
"""

from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class AccountTokens:
    """Signed, time-limited tokens for magic links and password reset.

    Args:
        secret_key: The application secret key (same one used for JWT signing).
        max_age: Default token lifetime in seconds (default: 1 hour).
    """

    def __init__(self, secret_key: str, max_age: int = 3600) -> None:
        self._max_age = max_age
        self._signer = URLSafeTimedSerializer(secret_key, salt="urauth.account")

    def generate(self, payload: str) -> str:
        """Return a signed, URL-safe token encoding *payload*.

        *payload* is typically a user ID or email address.
        Token lifetime is controlled by ``max_age`` on :meth:`verify`.
        """
        return self._signer.dumps(payload)

    def verify(self, token: str, *, max_age: int | None = None) -> str:
        """Verify *token* and return the original payload.

        Raises:
            ValueError: Token is invalid, tampered, or expired.
        """
        age = max_age if max_age is not None else self._max_age
        try:
            return self._signer.loads(token, max_age=age)
        except SignatureExpired as exc:
            raise ValueError("Token has expired") from exc
        except BadSignature as exc:
            raise ValueError("Invalid or tampered token") from exc
