"""Pre-configured OAuth2/OIDC provider metadata."""

from __future__ import annotations

from typing import Any

PROVIDERS: dict[str, dict[str, Any]] = {
    "google": {
        "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
        "client_kwargs": {"scope": "openid email profile"},
    },
    "github": {
        "api_base_url": "https://api.github.com/",
        "access_token_url": "https://github.com/login/oauth/access_token",
        "authorize_url": "https://github.com/login/oauth/authorize",
        "client_kwargs": {"scope": "user:email"},
        "userinfo_endpoint": "https://api.github.com/user",
    },
    "microsoft": {
        "server_metadata_url": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
        "client_kwargs": {"scope": "openid email profile"},
    },
    "apple": {
        "authorize_url": "https://appleid.apple.com/auth/authorize",
        "access_token_url": "https://appleid.apple.com/auth/token",
        "client_kwargs": {"scope": "name email", "response_mode": "form_post"},
    },
    "discord": {
        "api_base_url": "https://discord.com/api/",
        "access_token_url": "https://discord.com/api/oauth2/token",
        "authorize_url": "https://discord.com/api/oauth2/authorize",
        "client_kwargs": {"scope": "identify email"},
        "userinfo_endpoint": "https://discord.com/api/users/@me",
    },
    "gitlab": {
        "api_base_url": "https://gitlab.com/api/v4/",
        "access_token_url": "https://gitlab.com/oauth/token",
        "authorize_url": "https://gitlab.com/oauth/authorize",
        "client_kwargs": {"scope": "openid email profile"},
        "userinfo_endpoint": "https://gitlab.com/api/v4/user",
    },
}


def get_provider_defaults(name: str) -> dict[str, Any]:
    """Return default OAuth config for a known provider, or empty dict."""
    return dict(PROVIDERS.get(name.lower(), {}))
