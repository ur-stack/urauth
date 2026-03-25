from __future__ import annotations

import warnings
from typing import Any, Literal

from pydantic_settings import BaseSettings

SameSitePolicy = Literal["lax", "strict", "none"]

_HMAC_ALGORITHMS = {"HS256", "HS384", "HS512"}
_MIN_HMAC_KEY_LENGTH = 32
_WEAK_SECRETS = frozenset(
    {
        "secret",
        "password",
        "changeme",
        "change-me",
        "test",
        "key",
        "mysecret",
        "jwt-secret",
    }
)


class AuthConfig(BaseSettings):
    """Central configuration for urauth."""

    model_config = {"env_prefix": "AUTH_"}

    # JWT
    secret_key: str = "CHANGE-ME-IN-PRODUCTION"
    algorithm: str = "HS256"
    access_token_ttl: int = 900  # 15 minutes
    refresh_token_ttl: int = 604800  # 7 days
    token_issuer: str | None = None
    token_audience: str | None = None

    # Security
    environment: Literal["development", "production", "testing"] = "development"
    allow_insecure_key: bool = False

    # Refresh tokens
    rotate_refresh_tokens: bool = True

    # Password hashing
    password_hash_scheme: str = "bcrypt"

    # Session
    session_cookie_name: str = "session_id"
    session_ttl: int = 86400  # 24 hours
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: SameSitePolicy = "lax"

    # Cookie transport
    cookie_name: str = "access_token"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: SameSitePolicy = "lax"
    cookie_max_age: int | None = None
    cookie_domain: str | None = None
    cookie_path: str = "/"

    # CSRF
    csrf_enabled: bool = False
    csrf_cookie_name: str = "csrf_token"
    csrf_header_name: str = "X-CSRF-Token"

    # Multi-tenant
    tenant_enabled: bool = False
    tenant_header: str = "X-Tenant-ID"
    tenant_claim: str = "tenant_id"

    # Multi-tenant hierarchy
    tenant_hierarchy_enabled: bool = False
    tenant_hierarchy_levels: list[str] | None = None
    tenant_path_claim: str = "tenant_path"
    tenant_default_level: str = "tenant"

    # Auth router prefix
    auth_prefix: str = "/auth"

    def model_post_init(self, __context: Any) -> None:
        # In testing mode, default to allowing insecure keys
        if self.environment == "testing" and not self.allow_insecure_key:
            object.__setattr__(self, "allow_insecure_key", True)

        # In production mode, never allow insecure keys
        if self.environment == "production" and self.allow_insecure_key:
            raise ValueError(
                "urauth: allow_insecure_key=True is not permitted in production environment. "
                "Set AUTH_ENVIRONMENT to 'development' or 'testing' to use insecure keys."
            )

        if self.allow_insecure_key:
            if self.secret_key == "CHANGE-ME-IN-PRODUCTION":
                warnings.warn(
                    "urauth: Using default secret key 'CHANGE-ME-IN-PRODUCTION'. "
                    "Set AUTH_SECRET_KEY environment variable for production use.",
                    UserWarning,
                    stacklevel=2,
                )
            return

        if self.secret_key == "CHANGE-ME-IN-PRODUCTION":
            raise ValueError(
                "urauth: Default secret key 'CHANGE-ME-IN-PRODUCTION' is not allowed. "
                "Set AUTH_SECRET_KEY environment variable or pass a secure key. "
                "For development/testing, set allow_insecure_key=True."
            )

        key = self.secret_key.strip()
        if not key:
            raise ValueError("urauth: secret_key must not be empty or whitespace-only.")

        if key.lower() in _WEAK_SECRETS:
            raise ValueError(
                f"urauth: secret_key '{key}' is a commonly used weak secret. "
                "Use a random key of at least 32 bytes (e.g. `openssl rand -hex 32`)."
            )

        if self.algorithm in _HMAC_ALGORITHMS and len(self.secret_key) < _MIN_HMAC_KEY_LENGTH:
            raise ValueError(
                f"urauth: secret_key must be at least {_MIN_HMAC_KEY_LENGTH} characters "
                f"for HMAC algorithm {self.algorithm}. "
                "Use `openssl rand -hex 32` to generate a secure key."
            )
