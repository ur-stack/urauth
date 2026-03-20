"""urauth — unified authentication & authorization library."""

from urauth._version import __version__
from urauth.authn.password import PasswordHasher
from urauth.authz.permissions import PermissionManager
from urauth.authz.rbac import RBACManager
from urauth.authz.subject import Subject
from urauth.config import AuthConfig
from urauth.exceptions import (
    AuthError,
    ForbiddenError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UnauthorizedError,
)
from urauth.tokens.jwt import TokenService
from urauth.types import TokenPair, TokenPayload

__all__ = [
    "AuthConfig",
    "AuthError",
    "ForbiddenError",
    "InvalidTokenError",
    "PasswordHasher",
    "PermissionManager",
    "RBACManager",
    "Subject",
    "TokenExpiredError",
    "TokenPair",
    "TokenPayload",
    "TokenRevokedError",
    "TokenService",
    "UnauthorizedError",
    "__version__",
]
