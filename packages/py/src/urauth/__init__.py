"""urauth — unified authentication & authorization library."""

from urauth._version import __version__

# Core
from urauth.auth import Auth

# Authn
from urauth.authn.password import PasswordHasher

# Authorization system
from urauth.authz.checker import PermissionChecker, RoleExpandingChecker, StringChecker
from urauth.authz.permission_enum import PermissionEnum

# Authorization primitives
from urauth.authz.primitives import AllOf, AnyOf, Permission, Relation, Requirement, Role
from urauth.authz.roles import RoleRegistry
from urauth.config import AuthConfig
from urauth.context import AuthContext

# Exceptions
from urauth.exceptions import (
    AuthError,
    ForbiddenError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UnauthorizedError,
)

# Pipeline configuration
from urauth.pipeline import (
    MFA,
    APIKeyStrategy,
    BasicAuthStrategy,
    FallbackStrategy,
    Identifiers,
    JWTStrategy,
    MagicLinkLogin,
    OAuthLogin,
    OAuthProvider,
    OTPLogin,
    PasskeyLogin,
    PasswordLogin,
    PasswordReset,
    Pipeline,
    SessionStrategy,
)

# Rate limiting
from urauth.ratelimit import KeyStrategy, RateLimiter

# Tokens
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPair, TokenPayload

__all__ = [
    # Pipeline
    "MFA",
    "APIKeyStrategy",
    # Primitives
    "AllOf",
    "AnyOf",
    # Core
    "Auth",
    "AuthConfig",
    "AuthContext",
    # Exceptions
    "AuthError",
    "BasicAuthStrategy",
    "FallbackStrategy",
    "ForbiddenError",
    "Identifiers",
    "InvalidTokenError",
    "JWTStrategy",
    # Rate limiting
    "KeyStrategy",
    "MagicLinkLogin",
    "OAuthLogin",
    "OAuthProvider",
    "OTPLogin",
    "PasskeyLogin",
    # Authn
    "PasswordHasher",
    "PasswordLogin",
    "PasswordReset",
    "Permission",
    # Authorization
    "PermissionChecker",
    "PermissionEnum",
    "Pipeline",
    "RateLimiter",
    "Relation",
    "Requirement",
    "Role",
    "RoleExpandingChecker",
    "RoleRegistry",
    "SessionStrategy",
    "StringChecker",
    "TokenExpiredError",
    # Tokens
    "TokenPair",
    "TokenPayload",
    "TokenRevokedError",
    "TokenService",
    "UnauthorizedError",
    # Meta
    "__version__",
]
