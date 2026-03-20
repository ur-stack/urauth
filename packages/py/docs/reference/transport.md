# Transport

Transport classes handle how tokens are sent to and extracted from HTTP requests.

## Transport Protocol

The base protocol all transports implement.

::: fastapi_auth.transport.base.Transport

## BearerTransport

Extracts tokens from the `Authorization: Bearer` header.

::: fastapi_auth.transport.bearer.BearerTransport

## CookieTransport

Stores and extracts tokens using HTTP cookies.

::: fastapi_auth.transport.cookie.CookieTransport

## HeaderTransport

Extracts tokens from a custom header (e.g., `X-API-Key`).

::: fastapi_auth.transport.header.HeaderTransport

## HybridTransport

Tries multiple transports in order, using the first one that returns a token.

::: fastapi_auth.transport.hybrid.HybridTransport
