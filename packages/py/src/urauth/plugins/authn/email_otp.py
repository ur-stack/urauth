"""Email OTP (one-time password) authentication plugin."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from urauth.auth import Auth


class EmailOTPPlugin:
    """Email-based one-time password authentication.

    Generates a short numeric or alphanumeric code, delivers it via your
    email callable, then verifies it. Verification state (code + expiry) is
    stored via the provided ``store`` (any async key-value store — e.g. Redis,
    in-memory dict, or your DB).

    Usage::

        from urauth.plugins.authn import EmailOTPPlugin

        class RedisOTPStore:
            async def save(self, key: str, code: str, ttl: int) -> None:
                await redis.setex(key, ttl, code)
            async def get(self, key: str) -> str | None:
                return await redis.get(key)
            async def delete(self, key: str) -> None:
                await redis.delete(key)

        async def send_email(email: str, code: str) -> None:
            await mailer.send(to=email, body=f"Your code: {code}")

        auth = Auth(
            plugins=[
                EmailOTPPlugin(
                    send=send_email,
                    store=RedisOTPStore(),
                    digits=6,
                    ttl=300,
                )
            ],
            ...
        )

        await auth.email_otp.send_code("user@example.com")
        ok = await auth.email_otp.verify_code("user@example.com", "123456")
    """

    id = "email-otp"

    def __init__(
        self,
        *,
        send: Callable[[str, str], Any],
        store: Any,
        digits: int = 6,
        ttl: int = 300,
        code_type: str = "numeric",
        namespace: str = "emailotp",
    ) -> None:
        """
        Args:
            send: Async or sync callable ``(email, code) -> None``.
            store: Object implementing ``save(key, code, ttl)``, ``get(key)``,
                   ``delete(key)`` — typically backed by Redis or a DB.
            digits: OTP length (default 6).
            ttl: Code lifetime in seconds (default 5 minutes).
            code_type: ``"numeric"`` (default), ``"alpha"``, or ``"alphanumeric"``.
            namespace: Key prefix for the store (default ``"emailotp"``).
        """
        self._send = send
        self._store = store
        self.digits = digits
        self.ttl = ttl
        self.code_type = code_type
        self.namespace = namespace

    def setup(self, auth: Auth) -> None:
        auth.email_otp = self

    def _generate_code(self) -> str:
        if self.code_type == "numeric":
            return "".join(secrets.choice("0123456789") for _ in range(self.digits))
        if self.code_type == "alpha":
            return "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(self.digits))
        return "".join(
            secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(self.digits)
        )

    def _store_key(self, email: str) -> str:
        return f"{self.namespace}:{email}"

    async def send_code(self, email: str) -> None:
        """Generate a code, store it, and deliver it to *email*."""
        code = self._generate_code()
        await self._store.save(self._store_key(email), code, self.ttl)
        result = self._send(email, code)
        if hasattr(result, "__await__"):
            await result  # type: ignore[union-attr]

    async def verify_code(self, email: str, code: str) -> bool:
        """Verify *code* for *email*. Returns ``True`` on success and invalidates the code."""
        stored = await self._store.get(self._store_key(email))
        if stored is None:
            return False
        import hmac as _hmac

        valid = _hmac.compare_digest(stored.lower(), code.lower())
        if valid:
            await self._store.delete(self._store_key(email))
        return valid
