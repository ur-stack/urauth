"""OIDC Provider plugin — expose urauth as an OpenID Connect identity provider.

This plugin is a scaffold. Implementing a full OIDC provider requires:
- Authorization endpoint (code / implicit / hybrid flows)
- Token endpoint (code exchange, refresh)
- UserInfo endpoint
- JWKS endpoint (public keys)
- Discovery document (``/.well-known/openid-configuration``)
- Client registration (static or dynamic RFC 7591)

Recommended library: ``authlib`` (``pip install Authlib``) for the heavy lifting.

Usage (once implemented)::

    from urauth.plugins.enterprise import OIDCProviderPlugin

    auth = Auth(
        plugins=[
            OIDCProviderPlugin(
                issuer="https://auth.mycompany.com",
                clients=[
                    {"client_id": "...", "client_secret": "...", "redirect_uris": [...]},
                ],
            )
        ],
        ...
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth


class OIDCProviderPlugin:
    """Scaffold for exposing urauth as an OIDC identity provider.

    .. note::
        This plugin is not yet fully implemented. It provides the interface
        contract for a future implementation. Consider using ``authlib`` for
        production-grade OIDC provider functionality.
    """

    id = "oidc-provider"

    def __init__(
        self,
        *,
        issuer: str,
        clients: list[dict[str, Any]] | None = None,
        scopes_supported: list[str] | None = None,
        backend: Any = None,
    ) -> None:
        self.issuer = issuer
        self.clients = clients or []
        self.scopes_supported = scopes_supported or ["openid", "email", "profile"]
        self._backend = backend

    def setup(self, auth: Auth) -> None:
        auth.oidc_provider = self

    def discovery_document(self) -> dict[str, Any]:
        """Return the OpenID Connect discovery document."""
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "scopes_supported": self.scopes_supported,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        }

    async def authorize(self, request: Any) -> Any:
        raise NotImplementedError("Implement OIDC authorization endpoint")

    async def token(self, request: Any) -> Any:
        raise NotImplementedError("Implement OIDC token endpoint")

    async def userinfo(self, access_token: str) -> dict[str, Any]:
        raise NotImplementedError("Implement OIDC userinfo endpoint")

    def jwks(self) -> dict[str, Any]:
        raise NotImplementedError("Implement JWKS endpoint (public key set)")
