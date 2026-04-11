# Custom Auth Subclass

urauth uses your `Auth` subclass for user data access. Create a subclass and override the methods your application needs.

## SQLAlchemy Async

::: info Required packages
This guide uses async SQLAlchemy with asyncpg (PostgreSQL). Install:
```bash
pip install "urauth[fastapi]" sqlalchemy[asyncio] asyncpg
```
For SQLite (development): use `aiosqlite` instead of `asyncpg`, and `sqlite+aiosqlite:///./app.db` as the URL.
:::

```python
import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class UserModel(Base):
    __tablename__ = "users"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    roles: Mapped[list["RoleModel"]] = relationship("RoleModel", back_populates="user", lazy="selectin")

class RoleModel(Base):
    __tablename__ = "user_roles"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    
    user: Mapped["UserModel"] = relationship("UserModel", back_populates="roles")
```

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from urauth import Auth
from urauth.authn.password import PasswordHasher
from urauth.authz.primitives import Role

hasher = PasswordHasher()


class SQLAlchemyAuth(Auth):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], **kwargs):
        super().__init__(**kwargs)
        self._session_factory = session_factory

    async def get_user(self, user_id: str):
        async with self._session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.id == user_id)
            )
            return result.scalar_one_or_none()

    async def get_user_by_username(self, username: str):
        async with self._session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.email == username)
            )
            return result.scalar_one_or_none()

    async def verify_password(self, user, password: str) -> bool:
        return hasher.verify(password, user.hashed_password)

    async def get_user_roles(self, user) -> list[Role]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(RoleModel.name).where(RoleModel.user_id == user.id)
            )
            return [Role(name) for name in result.scalars().all()]
```

All overridable methods accept both sync and async implementations. urauth detects which you provide and handles both transparently.

## SQLModel

::: info Required packages
```bash
pip install "urauth[fastapi]" sqlmodel aiosqlite
```
:::

For SQLModel users, urauth ships a `SQLModelUserStore` mixin in `urauth.contrib.sqlmodel`. It automatically implements `get_user`, `get_user_by_username` (matched against the `email` field), and `verify_password` — no method overrides needed for basic auth.

```python
from datetime import datetime
from uuid import UUID, uuid4

from sqlmodel import Field, SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker

from urauth import Auth, JWT, Password
from urauth.backends.memory import MemoryTokenStore
from urauth.contrib.sqlmodel import SQLModelUserStore
from urauth.fastapi import FastAuth


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


# Mixin composition — no method overrides needed for basic auth
class MyAuth(Auth, SQLModelUserStore):
    pass


engine = create_async_engine("sqlite+aiosqlite:///./app.db")
session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

core = MyAuth(
    session_factory=session_factory,
    user_model=User,
    method=JWT(ttl=900, refresh_ttl=604800, store=MemoryTokenStore()),
    secret_key="...",
    password=Password(),
)

auth = FastAuth(core)
```

`SQLModelUserStore` reads `user.email` for username lookups and `user.hashed_password` for verification. Override any of the three methods on `MyAuth` if your schema uses different field names or requires custom logic.

## MongoDB Motor

::: info Required packages
```bash
pip install "urauth[fastapi]" motor
```
:::

```python
from urauth import Auth
from urauth.authn.password import PasswordHasher
from urauth.authz.primitives import Role

hasher = PasswordHasher()


class MongoAuth(Auth):
    def __init__(self, collection, **kwargs):
        super().__init__(**kwargs)
        self._collection = collection

    async def get_user(self, user_id: str):
        doc = await self._collection.find_one({"_id": user_id})
        if doc:
            return UserFromDoc(doc)
        return None

    async def get_user_by_username(self, username: str):
        doc = await self._collection.find_one({"email": username})
        if doc:
            return UserFromDoc(doc)
        return None

    async def verify_password(self, user, password: str) -> bool:
        return hasher.verify(password, user.hashed_password)

    async def get_user_roles(self, user) -> list[Role]:
        return [Role(name) for name in user.roles]
```

## Redis Token Store

The `TokenStore` protocol defines how tokens are tracked for revocation. Here is a Redis implementation:

```python
import time

from redis.asyncio import Redis


class RedisTokenStore:
    """TokenStore protocol implementation backed by Redis."""

    def __init__(self, redis: Redis, prefix: str = "token:"):
        self._redis = redis
        self._prefix = prefix

    async def is_revoked(self, jti: str) -> bool:
        return await self._redis.exists(f"{self._prefix}revoked:{jti}") > 0

    async def revoke(self, jti: str, expires_at: float) -> None:
        ttl = max(int(expires_at - time.time()), 1)
        await self._redis.setex(f"{self._prefix}revoked:{jti}", ttl, "1")

    async def revoke_all_for_user(self, user_id: str) -> None:
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

    async def get_sessions(self, user_id: str) -> list[str]:
        members = await self._redis.smembers(f"{self._prefix}user:{user_id}")
        return [m.decode() if isinstance(m, bytes) else m for m in members]
```

## Wiring It Up

Pass your `Auth` subclass and token store to `FastAuth`.

**SQLAlchemy variant:**

```python
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from urauth import JWT, Password
from urauth.fastapi import FastAuth

engine = create_async_engine("postgresql+asyncpg://...")
session_factory = async_sessionmaker(engine)
redis = Redis.from_url("redis://localhost:6379")

core = SQLAlchemyAuth(
    session_factory=session_factory,
    method=JWT(ttl=900, refresh_ttl=604800, store=RedisTokenStore(redis)),
    secret_key="production-secret",
    password=Password(),
)

auth = FastAuth(core)
```

**SQLModel variant:**

```python
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker

from urauth import JWT, Password
from urauth.fastapi import FastAuth

engine = create_async_engine("postgresql+asyncpg://...")
session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
redis = Redis.from_url("redis://localhost:6379")

core = MyAuth(
    session_factory=session_factory,
    user_model=User,
    method=JWT(ttl=900, refresh_ttl=604800, store=RedisTokenStore(redis)),
    secret_key="production-secret",
    password=Password(),
)

auth = FastAuth(core)
```

The same pattern works with any `Auth` subclass -- `MongoAuth`, an in-memory implementation for tests, or anything else.

## Overridable Hooks Reference

| Method | Required | Description |
|--------|----------|-------------|
| `get_user(user_id)` | Yes | Load user by ID |
| `get_user_by_username(username)` | Yes | Load user by username/email (for login) |
| `verify_password(user, password)` | Yes | Verify password against stored hash |
| `get_user_roles(user)` | No | Load roles; default reads `user.roles` |
| `get_user_permissions(user)` | No | Load direct permissions beyond role-derived ones |
| `get_user_relations(user)` | No | Load Zanzibar relations |
| `check_relation(user, relation, resource_id)` | No | Check a specific relation to a resource |
| `get_user_by_api_key(key)` | No | Load user by API key (for `APIKey` method) |
| `get_or_create_oauth_user(info)` | No | Resolve OAuth identity to a user |
