# Middleware

HTTP middleware for CSRF protection and automatic token refresh.

## CSRFMiddleware

Double-submit cookie CSRF protection for cookie-based authentication.

::: urauth.fastapi.middleware.CSRFMiddleware

## TokenRefreshMiddleware

Automatically refreshes near-expiry access tokens in cookies.

::: urauth.fastapi.middleware.TokenRefreshMiddleware
