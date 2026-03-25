# Tokens

JWT token creation, validation, lifecycle management, and revocation.

## TokenLifecycle

Unified entry point for all token operations: issue, validate, refresh, and revoke. Coordinates JWT creation/validation with store-based revocation tracking so callers never orchestrate multiple objects directly.


> **`urauth.tokens.lifecycle.TokenLifecycle`** — See source code for full API.


## IssueRequest

Parameters for issuing a new token pair (login, OAuth callback, etc.).


> **`urauth.tokens.lifecycle.IssueRequest`** — See source code for full API.


## IssuedTokenPair

Token pair enriched with `family_id` for session reference.


> **`urauth.tokens.lifecycle.IssuedTokenPair`** — See source code for full API.


## TokenService

Low-level JWT creation and validation. Typically accessed via `TokenLifecycle.jwt` rather than used directly.


> **`urauth.tokens.jwt.TokenService`** — See source code for full API.


## TokenPayload

Typed representation of a decoded access token.


> **`urauth.types.TokenPayload`** — See source code for full API.


## TokenPair

An access + refresh token pair returned by login and refresh operations.


> **`urauth.types.TokenPair`** — See source code for full API.

