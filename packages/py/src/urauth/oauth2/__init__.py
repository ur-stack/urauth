"""OAuth 2.0 / OIDC layer — provider client, credentials, linked identities."""

from urauth.oauth2.client import OAuthManager, OAuthUserInfo
from urauth.oauth2.providers import get_provider_defaults

__all__ = ["OAuthManager", "OAuthUserInfo", "get_provider_defaults"]
