"""Magic link authentication plugin.

Wraps :class:`~urauth.account.tokens.AccountTokens` for magic link generation
and verification. You supply the email delivery callable; this plugin handles
the signing and expiry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from urauth.auth import Auth


class MagicLinkPlugin:
    """Signed, time-limited magic link authentication.

    Usage::

        import httpx
        from urauth.plugins.authn import MagicLinkPlugin

        async def send_email(email: str, link: str) -> None:
            await mailer.send(to=email, subject="Sign in", body=link)

        auth = Auth(
            plugins=[
                MagicLinkPlugin(
                    send=send_email,
                    base_url="https://myapp.com/auth/magic",
                    ttl=900,  # 15 min
                )
            ],
            ...
        )

        # Initiate magic link flow
        msg = await auth.magic_link.send_link("user@example.com")

        # Verify token from query string
        user_id = auth.magic_link.verify(token)
    """

    id = "magic-link"

    def __init__(
        self,
        *,
        send: Callable[[str, str], Any] | None = None,
        base_url: str = "/auth/magic-link/verify",
        ttl: int = 900,
        token_param: str = "token",
    ) -> None:
        """
        Args:
            send: Async or sync callable ``(email, link) -> None`` that delivers
                  the magic link to the user. If ``None``, you must call
                  ``generate_link()`` and deliver it yourself.
            base_url: Base URL for the magic link; token is appended as a query param.
            ttl: Token lifetime in seconds (default 15 minutes).
            token_param: Query parameter name (default ``"token"``).
        """
        self._send = send
        self.base_url = base_url
        self.ttl = ttl
        self.token_param = token_param
        self._tokens: Any = None

    def setup(self, auth: Auth) -> None:
        from urauth.account.tokens import AccountTokens

        self._tokens = AccountTokens(secret_key=auth.secret_key, max_age=self.ttl)
        auth.magic_link = self

    def generate_token(self, payload: str) -> str:
        """Return a signed token encoding *payload* (typically a user ID or email)."""
        assert self._tokens is not None, "MagicLinkPlugin.setup() was not called"
        return self._tokens.generate(payload)

    def generate_link(self, payload: str) -> str:
        """Return the full magic link URL (token appended as a query string)."""
        token = self.generate_token(payload)
        sep = "&" if "?" in self.base_url else "?"
        return f"{self.base_url}{sep}{self.token_param}={token}"

    def verify(self, token: str, *, max_age: int | None = None) -> str:
        """Verify *token* and return the original payload.

        Raises:
            ValueError: Token is invalid, tampered, or expired.
        """
        assert self._tokens is not None, "MagicLinkPlugin.setup() was not called"
        return self._tokens.verify(token, max_age=max_age)

    async def send_link(self, email: str) -> str:
        """Generate a magic link and deliver it via the configured ``send`` callable.

        Returns the link URL so callers can log or inspect it.

        Raises:
            RuntimeError: ``send`` callable was not provided.
        """
        if self._send is None:
            raise RuntimeError(
                "MagicLinkPlugin requires a send= callable. "
                "Provide one at plugin construction or use generate_link() directly."
            )
        link = self.generate_link(email)
        result = self._send(email, link)
        if hasattr(result, "__await__"):
            await result  # type: ignore[union-attr]
        return link
