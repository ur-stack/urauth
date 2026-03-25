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
from urauth.authz.primitives import AllOf, AnyOf, Permission, Relation, RelationTuple, Requirement, Role
from urauth.authz.relation_enum import RelationEnum
from urauth.authz.roles import RoleRegistry
from urauth.config import AuthConfig
from urauth.context import AuthContext

# Events
from urauth.events import AuthEvent, AuthEventHandler, NullEventHandler

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
    APIKeyStrategy,
    BasicAuthStrategy,
    FallbackStrategy,
    Identifiers,
    JWTStrategy,
    MagicLinkLogin,
    MFAMethod,
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

# Tenant hierarchy
from urauth.tenant import TenantDefaults, TenantHierarchy, TenantLevel, TenantNode, TenantPath
from urauth.tenant.defaults import RoleTemplate

# Tokens
from urauth.tokens.jwt import TokenService
from urauth.tokens.lifecycle import IssuedTokenPair, IssueRequest, TokenLifecycle
from urauth.types import TokenPair, TokenPayload

__all__ = [
    # Pipeline
    "MFA",
    "APIKeyStrategy",
    # Primitives
    "AllOf",
    "AnyOf",
    # Events
    "AuthEvent",
    "AuthEventHandler",
    "NullEventHandler",
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
    "IssueRequest",
    "IssuedTokenPair",
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
    "RelationEnum",
    "RelationTuple",
    "Requirement",
    "Role",
    "RoleExpandingChecker",
    "RoleRegistry",
    "RoleTemplate",
    "SessionStrategy",
    "StringChecker",
    # Tenant hierarchy
    "TenantDefaults",
    "TenantHierarchy",
    "TenantLevel",
    "TenantNode",
    "TenantPath",
    "TokenExpiredError",
    # Tokens
    "TokenLifecycle",
    "TokenPair",
    "TokenPayload",
    "TokenRevokedError",
    "TokenService",
    "UnauthorizedError",
    # Meta
    "__version__",
]
