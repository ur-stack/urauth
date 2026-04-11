"""OAuthManager using httpx for OAuth2/OIDC flows."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

import httpx

from urauth.oauth2.providers import get_provider_defaults


@dataclass
class OAuthUserInfo:
    """Normalized user info from an OAuth provider."""

    provider: str
    sub: str
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    picture: str | None = None
    raw: dict[str, Any] | None = None


class OAuthManager:
    """Manages OAuth2/OIDC provider registrations and auth flows.

    Uses httpx directly instead of authlib. Requires a session-like
    storage mechanism for state and PKCE storage.
    """

    def __init__(self) -> None:
        self._providers: dict[str, dict[str, Any]] = {}
        self._metadata_cache: dict[str, dict[str, Any]] = {}

    def register(
        self,
        name: str,
        *,
        client_id: str,
        client_secret: str,
        **kwargs: Any,
    ) -> None:
        """Register an OAuth provider. Known providers get pre-filled defaults."""
        if name in self._providers:
            return

        defaults = get_provider_defaults(name)
        defaults.update(kwargs)

        self._providers[name] = {
            "client_id": client_id,
            "client_secret": client_secret,
            **defaults,
        }

    def _get_provider(self, name: str) -> dict[str, Any]:
        if name not in self._providers:
            raise ValueError(f"OAuth provider '{name}' not registered")
        return self._providers[name]

    async def _discover_metadata(self, provider_name: str) -> dict[str, Any]:
        """Fetch and cache OIDC discovery document for a provider."""
        if provider_name in self._metadata_cache:
            return self._metadata_cache[provider_name]

        config = self._get_provider(provider_name)
        metadata_url = config.get("server_metadata_url")
        if not metadata_url:
            return {}

        async with httpx.AsyncClient() as client:
            resp = await client.get(metadata_url)
            resp.raise_for_status()
            metadata = resp.json()

        self._metadata_cache[provider_name] = metadata
        return metadata

    async def _get_endpoint(self, provider_name: str, endpoint_key: str) -> str | None:
        """Get an endpoint URL from provider config or OIDC metadata."""
        config = self._get_provider(provider_name)

        # Check direct config first
        if endpoint_key in config:
            return config[endpoint_key]

        # Map our config keys to OIDC metadata keys
        key_map = {
            "authorize_url": "authorization_endpoint",
            "access_token_url": "token_endpoint",
            "userinfo_endpoint": "userinfo_endpoint",
        }
        metadata_key = key_map.get(endpoint_key, endpoint_key)

        metadata = await self._discover_metadata(provider_name)
        return metadata.get(metadata_key)

    def build_authorize_params(self, provider: str, redirect_uri: str) -> tuple[str, str, str]:
        """Build authorization URL, state, and code_verifier for the provider.

        Returns (authorize_url, state, code_verifier). The caller is responsible
        for storing state and code_verifier in the session.
        """
        config = self._get_provider(provider)

        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)

        return state, code_verifier, config.get("client_id", "")

    async def authorize_redirect_url(self, provider: str, redirect_uri: str, state: str, code_verifier: str) -> str:
        """Build the full authorization URL."""
        config = self._get_provider(provider)

        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        authorize_url = await self._get_endpoint(provider, "authorize_url")
        if not authorize_url:
            raise ValueError(f"No authorize_url configured for provider '{provider}'")

        client_kwargs = config.get("client_kwargs", {})
        scope = client_kwargs.get("scope", "openid email profile")

        params = {
            "client_id": config["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        for key in ("response_mode",):
            if key in client_kwargs:
                params[key] = client_kwargs[key]

        url = str(httpx.URL(authorize_url).copy_merge_params(params))
        return url

    async def exchange_code(
        self,
        provider: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OAuthUserInfo:
        """Exchange authorization code for tokens and fetch userinfo."""
        config = self._get_provider(provider)

        token_url = await self._get_endpoint(provider, "access_token_url")
        if not token_url:
            raise ValueError(f"No access_token_url configured for provider '{provider}'")

        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code_verifier": code_verifier,
        }

        async with httpx.AsyncClient() as client:
            token_resp = await client.post(
                token_url,
                data=token_data,
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            token_json = token_resp.json()

        access_token = token_json.get("access_token")
        if not access_token:
            raise ValueError("No access_token in token response")

        # Fetch userinfo
        userinfo_url = await self._get_endpoint(provider, "userinfo_endpoint")
        userinfo: dict[str, Any] = {}

        if userinfo_url:
            async with httpx.AsyncClient() as client:
                userinfo_resp = await client.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if userinfo_resp.status_code == 200:
                    userinfo = userinfo_resp.json()

        return OAuthUserInfo(
            provider=provider,
            sub=str(userinfo.get("sub") or userinfo.get("id") or ""),
            email=userinfo.get("email"),
            email_verified=userinfo.get("email_verified", False),
            name=userinfo.get("name"),
            picture=userinfo.get("picture") or userinfo.get("avatar_url"),
            raw=userinfo,
        )
