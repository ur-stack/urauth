# Tokens

JWT token creation, validation, refresh management, and revocation.

## TokenService

Creates and validates JWT access and refresh tokens.

::: urauth.tokens.jwt.TokenService

## RefreshService

Handles refresh token rotation with reuse detection.

::: urauth.tokens.refresh.RefreshService

## RevocationService

Manages token revocation and blacklisting.

::: urauth.tokens.revocation.RevocationService

## TokenPayload

Typed representation of a decoded access token.

::: urauth.types.TokenPayload

## TokenPair

An access + refresh token pair returned by login and refresh operations.

::: urauth.types.TokenPair
