"""Phone number (SMS OTP) authentication plugin."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from urauth.auth import Auth


class PhoneNumberPlugin:
    """Phone number + SMS OTP authentication.

    Follows the same pattern as :class:`~urauth.plugins.authn.EmailOTPPlugin`:
    you provide an SMS delivery callable and a key-value store. Codes are
    generated, stored with a TTL, and consumed on first successful verification.

    Usage::

        from urauth.plugins.authn import PhoneNumberPlugin

        async def send_sms(phone: str, code: str) -> None:
            await twilio.messages.create(to=phone, body=f"Your code: {code}")

        auth = Auth(
            plugins=[
                PhoneNumberPlugin(
                    send=send_sms,
                    store=redis_store,
                    digits=6,
                    ttl=300,
                )
            ],
            ...
        )

        await auth.phone.send_code("+15551234567")
        ok = await auth.phone.verify_code("+15551234567", "123456")
    """

    id = "phone-number"

    def __init__(
        self,
        *,
        send: Callable[[str, str], Any],
        store: Any,
        digits: int = 6,
        ttl: int = 300,
        namespace: str = "phoneotp",
    ) -> None:
        self._send = send
        self._store = store
        self.digits = digits
        self.ttl = ttl
        self.namespace = namespace

    def setup(self, auth: Auth) -> None:
        auth.phone = self

    def _generate_code(self) -> str:
        return "".join(secrets.choice("0123456789") for _ in range(self.digits))

    def _store_key(self, phone: str) -> str:
        return f"{self.namespace}:{phone}"

    async def send_code(self, phone: str) -> None:
        """Generate a code, store it, and send it to *phone* via SMS."""
        code = self._generate_code()
        await self._store.save(self._store_key(phone), code, self.ttl)
        result = self._send(phone, code)
        if hasattr(result, "__await__"):
            await result  # type: ignore[union-attr]

    async def verify_code(self, phone: str, code: str) -> bool:
        """Verify *code* for *phone*. Consumes the code on success."""
        stored = await self._store.get(self._store_key(phone))
        if stored is None:
            return False
        import hmac as _hmac

        valid = _hmac.compare_digest(stored, code)
        if valid:
            await self._store.delete(self._store_key(phone))
        return valid
