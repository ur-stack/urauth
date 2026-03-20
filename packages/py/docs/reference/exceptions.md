# Exceptions

All exceptions inherit from `AuthError`, which extends FastAPI's `HTTPException`.

## AuthError

Base exception for all authentication/authorization errors.

::: fastapi_auth.exceptions.AuthError

## InvalidTokenError

Raised when a token cannot be decoded or has an invalid structure.

::: fastapi_auth.exceptions.InvalidTokenError

## TokenExpiredError

Raised when a token has passed its expiration time.

::: fastapi_auth.exceptions.TokenExpiredError

## TokenRevokedError

Raised when a revoked token is used.

::: fastapi_auth.exceptions.TokenRevokedError

## UnauthorizedError

Raised when no authentication credentials are provided.

::: fastapi_auth.exceptions.UnauthorizedError

## ForbiddenError

Raised when the user is authenticated but lacks required permissions, roles, or scopes.

::: fastapi_auth.exceptions.ForbiddenError
