# Custom Backends

fastapi-auth uses protocols, not base classes. Implement the required methods and plug in your backend.

## SQLAlchemy Async Backend

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_auth.authn.password import PasswordHasher

hasher = PasswordHasher()


class SQLAlchemyBackend:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def get_by_id(self, user_id: str):
        async with self._session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.id == user_id)
            )
            return result.scalar_one_or_none()

    async def get_by_username(self, username: str):
        async with self._session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.email == username)
            )
            return result.scalar_one_or_none()

    async def verify_password(self, user, password: str) -> bool:
        return hasher.verify(password, user.hashed_password)

    async def create_oauth_user(self, info):
        """Optional: create user from OAuth info."""
        async with self._session_factory() as session:
            user = UserModel(
                email=info.email,
                is_active=True,
                is_verified=info.email_verified,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user
```

## MongoDB Motor Backend

```python
from fastapi_auth.authn.password import PasswordHasher

hasher = PasswordHasher()


class MongoBackend:
    def __init__(self, collection):
        self._collection = collection

    async def get_by_id(self, user_id: str):
        doc = await self._collection.find_one({"_id": user_id})
        if doc:
            return UserFromDoc(doc)
        return None

    async def get_by_username(self, username: str):
        doc = await self._collection.find_one({"email": username})
        if doc:
            return UserFromDoc(doc)
        return None

    async def verify_password(self, user, password: str) -> bool:
        return hasher.verify(password, user.hashed_password)
```

## Redis Token Store

The `TokenStore` protocol has six methods. Here's a Redis implementation:

```python
import json
import time

from redis.asyncio import Redis


class RedisTokenStore:
    def __init__(self, redis: Redis, prefix: str = "token:"):
        self._redis = redis
        self._prefix = prefix

    async def is_revoked(self, jti: str) -> bool:
        return await self._redis.exists(f"{self._prefix}revoked:{jti}") > 0

    async def revoke(self, jti: str, expires_at: float) -> None:
        ttl = max(int(expires_at - time.time()), 1)
        await self._redis.setex(f"{self._prefix}revoked:{jti}", ttl, "1")

    async def revoke_all_for_user(self, user_id: str) -> None:
        # Get all token JTIs for this user and revoke them
        members = await self._redis.smembers(f"{self._prefix}user:{user_id}")
        pipe = self._redis.pipeline()
        for jti in members:
            pipe.setex(f"{self._prefix}revoked:{jti}", 86400, "1")
        await pipe.execute()

    async def add_token(
        self, jti: str, user_id: str, token_type: str,
        expires_at: float, family_id: str | None = None,
    ) -> None:
        ttl = max(int(expires_at - time.time()), 1)
        await self._redis.sadd(f"{self._prefix}user:{user_id}", jti)
        if family_id:
            await self._redis.setex(
                f"{self._prefix}family:{jti}", ttl, family_id
            )
            await self._redis.sadd(f"{self._prefix}fam:{family_id}", jti)

    async def get_family_id(self, jti: str) -> str | None:
        result = await self._redis.get(f"{self._prefix}family:{jti}")
        return result.decode() if result else None

    async def revoke_family(self, family_id: str) -> None:
        members = await self._redis.smembers(f"{self._prefix}fam:{family_id}")
        pipe = self._redis.pipeline()
        for jti in members:
            pipe.setex(f"{self._prefix}revoked:{jti}", 86400, "1")
        await pipe.execute()
```

## Wiring It Up

```python
from redis.asyncio import Redis
from fastapi_auth import FastAPIAuth, AuthConfig

redis = Redis.from_url("redis://localhost:6379")

auth = FastAPIAuth(
    SQLAlchemyBackend(session_factory),
    AuthConfig(secret_key="production-secret"),
    token_store=RedisTokenStore(redis),
)
```
