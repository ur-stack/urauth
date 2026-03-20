from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings

SameSitePolicy = Literal["lax", "strict", "none"]


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

    # Auth router prefix
    auth_prefix: str = "/auth"
