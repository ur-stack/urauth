# Rate Limiting

Framework-agnostic rate limiting with a FastAPI integration layer. The core `RateLimiter` and `KeyStrategy` work independently of any web framework, while `RateLimit` provides a FastAPI dependency for route-level throttling.

## RateLimiter

The core rate limiter implementation.

::: urauth.ratelimit.RateLimiter

## KeyStrategy

Determines how rate limit keys are generated (e.g., by IP, by user, by API key).

::: urauth.ratelimit.KeyStrategy

## RateLimit (FastAPI)

FastAPI dependency for applying rate limits to individual routes.

::: urauth.fastapi.ratelimit.RateLimit
