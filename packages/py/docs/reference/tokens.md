# Tokens

JWT token creation, validation, and refresh management.

## TokenService

Creates and validates JWT access and refresh tokens.

::: fastapi_auth.tokens.jwt.TokenService

## RefreshService

Handles refresh token rotation with reuse detection.

::: fastapi_auth.tokens.refresh.RefreshService

## TokenPayload

Typed representation of a decoded access token.

::: fastapi_auth.types.TokenPayload

## TokenPair

An access + refresh token pair returned by login and refresh operations.

::: fastapi_auth.types.TokenPair
