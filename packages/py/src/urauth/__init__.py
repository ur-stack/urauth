"""urauth — unified authentication & authorization library."""

from urauth._version import __version__

# Core
from urauth.auth import Auth

# Identity & Auth layer
from urauth.identity.password import PasswordHasher

# Authorization system
from urauth.authz.checker import PermissionChecker, RoleExpandingChecker, StringChecker
from urauth.authz.permission_enum import PermissionEnum

# Authorization primitives
from urauth.authz.primitives import AllOf, AnyOf, Permission, Relation, RelationTuple, Requirement, Role
from urauth.authz.relation_enum import RelationEnum
from urauth.authz.roles import RoleRegistry

# Config (internal, kept for backward compatibility)
from urauth.config import AuthConfig
from urauth.context import AuthContext

# Audit & Security Events layer
from urauth.audit.events import AuthEvent, AuthEventHandler, NullEventHandler, StructlogEventHandler

# Exceptions
from urauth.exceptions import (
    AuthError,
    ForbiddenError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UnauthorizedError,
)

# Auth methods (was strategies)
# OAuth providers
from urauth.methods import (
    JWT,
    MFA,
    OTP,
    TOTP,
    AccountLinking,
    APIKey,
    Apple,
    BasicAuth,
    DeliveryChannel,
    Discord,
    Email,
    Fallback,
    GitHub,
    GitLab,
    Google,
    Identifiers,
    Identity,
    MagicLink,
    Method,
    Microsoft,
    OAuth,
    OAuthProvider,
    Passkey,
    Password,
    Phone,
    ResetablePassword,
    Session,
    Username,
)

# Plugin system
from urauth.plugin import PluginRegistry, UrAuthPlugin

# Rate limiting
from urauth.ratelimit import KeyStrategy, RateLimiter

# Results
from urauth.results import AuthResult, LoginResult, MessageResult, MFARequiredResult, ResetSessionResult

# Tenant hierarchy
from urauth.tenant import TenantDefaults, TenantHierarchy, TenantLevel, TenantNode, TenantPath
from urauth.tenant.defaults import RoleTemplate

# Tokens
from urauth.tokens.jwt import TokenService
from urauth.tokens.lifecycle import IssuedTokenPair, IssueRequest, TokenLifecycle
from urauth.types import TokenPair, TokenPayload

# User data mixin
from urauth.users import UserDataMixin

# Account lifecycle layer
from urauth.account import AccountLifecycle, AccountStore, AccountTokens, DeletionResult, SuspendResult

# API key management layer
from urauth.apikeys import ApiKeyManager, ApiKeyRecord, ApiKeyStore, CreatedApiKey

# MFA layer
from urauth.mfa import TOTP, BackupCodeStore, BackupCodes, GeneratedCodes, StepUpToken

# Storage layer
from urauth.storage import CachedTokenStore, MemorySessionStore, MemoryTokenStore

__all__ = [
    # Auth methods
    "JWT",
    "MFA",
    "OTP",
    "TOTP",
    "APIKey",
    "AccountLinking",
    "BasicAuth",
    "DeliveryChannel",
    "Email",
    "Fallback",
    "Identifiers",
    "Identity",
    "MagicLink",
    "Method",
    "OAuth",
    "Passkey",
    "Password",
    "Phone",
    "ResetablePassword",
    "Session",
    "Username",
    # OAuth providers
    "Apple",
    "Discord",
    "GitHub",
    "GitLab",
    "Google",
    "Microsoft",
    "OAuthProvider",
    # Primitives
    "AllOf",
    "AnyOf",
    # Events
    "AuthEvent",
    "AuthEventHandler",
    "NullEventHandler",
    "StructlogEventHandler",
    # Core
    "Auth",
    "AuthConfig",
    "AuthContext",
    # Results
    "AuthResult",
    "LoginResult",
    "MFARequiredResult",
    "MessageResult",
    "ResetSessionResult",
    # Exceptions
    "AuthError",
    "ForbiddenError",
    "InvalidTokenError",
    "IssueRequest",
    "IssuedTokenPair",
    # Plugin system
    "PluginRegistry",
    "UrAuthPlugin",
    # Rate limiting
    "KeyStrategy",
    # Authn
    "PasswordHasher",
    "Permission",
    # Authorization
    "PermissionChecker",
    "PermissionEnum",
    "RateLimiter",
    "Relation",
    "RelationEnum",
    "RelationTuple",
    "Requirement",
    "Role",
    "RoleExpandingChecker",
    "RoleRegistry",
    "RoleTemplate",
    "Session",
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
    # User data mixin
    "UserDataMixin",
    # Account lifecycle
    "AccountLifecycle",
    "AccountStore",
    "AccountTokens",
    "DeletionResult",
    "SuspendResult",
    # API keys
    "ApiKeyManager",
    "ApiKeyRecord",
    "ApiKeyStore",
    "CreatedApiKey",
    # MFA
    "TOTP",
    "BackupCodeStore",
    "BackupCodes",
    "GeneratedCodes",
    "StepUpToken",
    # Storage
    "CachedTokenStore",
    "MemorySessionStore",
    "MemoryTokenStore",
    # Meta
    "__version__",
]
