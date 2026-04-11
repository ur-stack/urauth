"""Generic OAuth2 authentication plugin.

Wraps :class:`~urauth.oauth2.client.OAuth2Client` for provider-agnostic
OAuth2 login. Pre-configured shortcuts for common providers are available
via the ``from_*`` class methods.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth


@dataclass
class OAuthSession:
    """State produced by :meth:`OAuthPlugin.start_flow`.

    Store this server-side (e.g. in the session) keyed by ``state``, then
    retrieve and pass it to :meth:`OAuthPlugin.complete_flow` on the callback.
    """

    state: str
    code_verifier: str | None  # PKCE
    provider: str
    redirect_uri: str


class OAuthPlugin:
    """Generic OAuth2 / OIDC login plugin.

    Usage::

        from urauth.plugins.authn import OAuthPlugin
        from urauth.oauth2.providers import get_provider_defaults

        auth = Auth(
            plugins=[
                OAuthPlugin.from_github(
                    client_id=os.environ["GITHUB_CLIENT_ID"],
                    client_secret=os.environ["GITHUB_CLIENT_SECRET"],
                    redirect_uri="https://myapp.com/auth/github/callback",
                ),
            ],
            ...
        )

        # 1. Start the flow
        session = await auth.oauth.start_flow("github")
        redirect_to = session.authorization_url  # send user here

        # 2. Handle the callback
        user_info = await auth.oauth.complete_flow(
            provider="github",
            code=request.query_params["code"],
            state=request.query_params["state"],
            stored_state=session.state,
            code_verifier=session.code_verifier,
        )
    """

    id = "oauth"

    def __init__(
        self,
        *,
        provider: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
        extra_params: dict[str, str] | None = None,
        use_pkce: bool = True,
    ) -> None:
        self.provider = provider
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._extra_params = extra_params or {}
        self._use_pkce = use_pkce
        self._client: Any = None

    def setup(self, auth: Auth) -> None:
        from urauth.oauth2.client import OAuth2Client

        self._client = OAuth2Client(
            provider=self.provider,
            client_id=self._client_id,
            client_secret=self._client_secret,
            redirect_uri=self._redirect_uri,
            scopes=self._scopes,
        )
        # Allow multiple OAuth plugins keyed by provider name
        if not hasattr(auth, "_oauth_plugins"):
            auth._oauth_plugins: dict[str, OAuthPlugin] = {}
        auth._oauth_plugins[self.provider] = self
        auth.oauth = _OAuthDispatcher(auth)

    async def get_authorization_url(self) -> tuple[str, str, str | None]:
        """Return ``(url, state, code_verifier)`` to start the OAuth flow."""
        import secrets

        state = secrets.token_urlsafe(32)
        code_verifier: str | None = None
        params: dict[str, str] = {"state": state, **self._extra_params}

        if self._use_pkce:
            import base64
            import hashlib

            code_verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        url = await self._client.get_authorization_url(**params)
        return url, state, code_verifier

    async def exchange_code(
        self,
        code: str,
        *,
        state: str,
        stored_state: str,
        code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange *code* for user info after validating *state*.

        Returns the normalised user info dict from the provider.

        Raises:
            ValueError: State mismatch (CSRF protection).
        """
        import hmac as _hmac

        if not _hmac.compare_digest(state, stored_state):
            raise ValueError("OAuth state mismatch — possible CSRF attack")

        tokens = await self._client.exchange_code(code, code_verifier=code_verifier)
        return await self._client.get_user_info(tokens["access_token"])

    # ── Provider shortcuts ────────────────────────────────────────────────────

    @classmethod
    def from_github(cls, *, client_id: str, client_secret: str, redirect_uri: str) -> OAuthPlugin:
        return cls(
            provider="github",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=["user:email"],
            use_pkce=False,  # GitHub doesn't support PKCE for web apps
        )

    @classmethod
    def from_google(cls, *, client_id: str, client_secret: str, redirect_uri: str) -> OAuthPlugin:
        return cls(
            provider="google",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=["openid", "email", "profile"],
            use_pkce=True,
        )

    @classmethod
    def from_discord(cls, *, client_id: str, client_secret: str, redirect_uri: str) -> OAuthPlugin:
        return cls(
            provider="discord",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=["identify", "email"],
            use_pkce=False,
        )

    @classmethod
    def from_microsoft(
        cls,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        tenant: str = "common",
    ) -> OAuthPlugin:
        return cls(
            provider="microsoft",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=["openid", "email", "profile"],
            extra_params={"tenant": tenant},
            use_pkce=True,
        )


class _OAuthDispatcher:
    """Proxy on ``auth.oauth`` that dispatches to the correct provider plugin."""

    def __init__(self, auth: Auth) -> None:
        self._auth = auth

    def _get(self, provider: str) -> OAuthPlugin:
        plugins: dict[str, OAuthPlugin] = getattr(self._auth, "_oauth_plugins", {})
        if provider not in plugins:
            raise KeyError(
                f"No OAuth plugin registered for provider '{provider}'. "
                f"Available: {list(plugins.keys())}"
            )
        return plugins[provider]

    async def get_authorization_url(self, provider: str) -> tuple[str, str, str | None]:
        """Return ``(url, state, code_verifier)`` for the named provider."""
        return await self._get(provider).get_authorization_url()

    async def exchange_code(
        self,
        provider: str,
        code: str,
        *,
        state: str,
        stored_state: str,
        code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange the callback code for user info."""
        return await self._get(provider).exchange_code(
            code, state=state, stored_state=stored_state, code_verifier=code_verifier
        )

    @property
    def providers(self) -> list[str]:
        return list(getattr(self._auth, "_oauth_plugins", {}).keys())
