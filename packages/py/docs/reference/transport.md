# Transport

Transport classes handle how tokens are extracted from HTTP requests. All transports implement the same protocol, making them interchangeable. Use `HybridTransport` to try multiple extraction methods in order.

## BearerTransport

Extracts tokens from the `Authorization: Bearer` header.


> **`urauth.fastapi.transport.bearer.BearerTransport`** — See source code for full API.


## CookieTransport

Stores and extracts tokens using HTTP cookies.


> **`urauth.fastapi.transport.cookie.CookieTransport`** — See source code for full API.


## HybridTransport

Tries multiple transports in order, using the first one that returns a token.


> **`urauth.fastapi.transport.hybrid.HybridTransport`** — See source code for full API.

