# Sessions

Server-side session and token storage backends. Use the in-memory stores for development and testing, and the Redis-backed stores for production.

## MemorySessionStore

In-memory session store for development and testing.


> **`urauth.backends.memory.MemorySessionStore`** — See source code for full API.


## RedisSessionStore

Redis-backed session store for production use.


> **`urauth.sessions.redis.RedisSessionStore`** — See source code for full API.


## MemoryTokenStore

In-memory token store for development and testing. Tracks issued and revoked tokens for refresh rotation.


> **`urauth.backends.memory.MemoryTokenStore`** — See source code for full API.

