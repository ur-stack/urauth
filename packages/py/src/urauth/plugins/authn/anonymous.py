"""Anonymous session plugin.

Creates temporary anonymous users before account creation.
Supports upgrading an anonymous session to a real account on signup.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from urauth.auth import Auth


class AnonymousPlugin:
    """Allow unauthenticated users to get a short-lived anonymous session.

    Useful for guest carts, in-progress form state, or A/B experiments
    before a user creates an account.

    The anonymous user ID is prefixed with ``prefix`` so the application
    can distinguish anonymous sessions from real accounts.

    Usage::

        from urauth.plugins.authn import AnonymousPlugin

        auth = Auth(
            plugins=[AnonymousPlugin(prefix="anon_", ttl=604800)],
            ...
        )

        # Issue an anonymous token (e.g. in a "guest" endpoint)
        token = await auth.anonymous.create_session()

        # After signup: revoke the anonymous session
        await auth.anonymous.upgrade(anon_token=old_token, real_user_id="usr_123")

        # Detect anonymous context
        if auth.anonymous.is_anonymous(context.token.sub):
            ...
    """

    id = "anonymous"

    def __init__(
        self,
        *,
        prefix: str = "anon_",
        ttl: int = 604_800,  # 7 days
    ) -> None:
        self.prefix = prefix
        self.ttl = ttl
        self._auth: Auth | None = None

    def setup(self, auth: Auth) -> None:
        self._auth = auth
        auth.anonymous = self

    def is_anonymous(self, user_id: str) -> bool:
        """Return ``True`` if *user_id* is an anonymous session ID."""
        return user_id.startswith(self.prefix)

    def new_id(self) -> str:
        """Return a fresh anonymous user ID (does not issue a token)."""
        return f"{self.prefix}{secrets.token_urlsafe(16)}"

    async def create_session(self) -> str:
        """Issue a signed access token for a new anonymous user.

        Returns the raw access token string. Store it client-side as
        you would a normal access token.
        """
        assert self._auth is not None, "AnonymousPlugin.setup() was not called"
        from urauth.tokens.lifecycle import IssueRequest

        anon_id = self.new_id()
        issued = await self._auth.lifecycle.issue(
            IssueRequest(user_id=anon_id, extra_claims={"anon": True})
        )
        return issued.access_token

    async def upgrade(self, *, anon_token: str, real_user_id: str) -> None:
        """Revoke the anonymous session after the user signs up or logs in.

        Call this immediately after creating the real user account so the
        anonymous session cannot be reused.
        """
        assert self._auth is not None, "AnonymousPlugin.setup() was not called"
        try:
            await self._auth.lifecycle.revoke(anon_token)
        except Exception:
            pass  # Already expired or invalid — not an error during upgrade
