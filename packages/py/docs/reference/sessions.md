# Sessions

Server-side session and token storage backends. Use the in-memory stores for development and testing, and the Redis-backed stores for production.

## MemorySessionStore

In-memory session store for development and testing.

::: urauth.sessions.memory.MemorySessionStore

## RedisSessionStore

Redis-backed session store for production use.

::: urauth.sessions.redis.RedisSessionStore

## MemoryTokenStore

In-memory token store for development and testing. Tracks issued and revoked tokens for refresh rotation.

::: urauth.backends.memory.MemoryTokenStore
