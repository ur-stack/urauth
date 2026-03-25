# Exceptions

All exceptions inherit from `AuthError`. Each maps to an appropriate HTTP status code and can be raised directly or will be raised automatically by guards and middleware.

## AuthError

Base exception for all authentication and authorization errors.


> **`urauth.exceptions.AuthError`** — See source code for full API.


## InvalidTokenError

Raised when a token cannot be decoded or has an invalid structure.


> **`urauth.exceptions.InvalidTokenError`** — See source code for full API.


## TokenExpiredError

Raised when a token has passed its expiration time.


> **`urauth.exceptions.TokenExpiredError`** — See source code for full API.


## TokenRevokedError

Raised when a revoked token is used.


> **`urauth.exceptions.TokenRevokedError`** — See source code for full API.


## UnauthorizedError

Raised when no authentication credentials are provided.


> **`urauth.exceptions.UnauthorizedError`** — See source code for full API.


## ForbiddenError

Raised when the user is authenticated but lacks the required permissions, roles, or scopes.


> **`urauth.exceptions.ForbiddenError`** — See source code for full API.

