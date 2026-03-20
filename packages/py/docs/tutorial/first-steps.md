# First Steps

In this tutorial you'll set up password-based JWT authentication from scratch.

## Install

```bash
pip install fastapi-auth
```

You also need an ASGI server:

```bash
pip install uvicorn
```

## Create a User Model

Your user model can be anything — a dataclass, a Pydantic model, an ORM object. The only requirement is that it has `id` and `is_active` properties.

```python
from dataclasses import dataclass, field
from fastapi_auth.authn.password import PasswordHasher

hasher = PasswordHasher()


@dataclass
class User:
    id: str
    username: str
    hashed_password: str
    is_active: bool = True
    is_verified: bool = False
    roles: list[str] = field(default_factory=list)
```

!!! info "Protocol, not base class"
    fastapi-auth uses `UserProtocol` — a runtime-checkable protocol that only requires `id` and `is_active`. You never inherit from a base class.

## Implement a User Backend

The `UserBackend` protocol requires three async methods:

```python
# In-memory store for this example
USERS: dict[str, User] = {
    "alice": User(
        id="1",
        username="alice",
        hashed_password=hasher.hash("secret"),
    ),
}


class MyBackend:
    async def get_by_id(self, user_id: str) -> User | None:  # (1)!
        for u in USERS.values():
            if u.id == user_id:
                return u
        return None

    async def get_by_username(self, username: str) -> User | None:  # (2)!
        return USERS.get(username)

    async def verify_password(self, user: User, password: str) -> bool:  # (3)!
        return hasher.verify(password, user.hashed_password)
```

1. Called when resolving a user from a JWT token.
2. Called during login to find the user by username or email.
3. Called during login to verify the password.

## Wire Up FastAPIAuth

```python
from fastapi import Depends, FastAPI
from fastapi_auth import AuthConfig, FastAPIAuth

auth = FastAPIAuth(
    MyBackend(),
    AuthConfig(secret_key="super-secret-key"),
)

app = FastAPI(lifespan=auth.lifespan())
app.include_router(auth.password_auth_router())


@app.get("/me")
async def me(user=Depends(auth.current_user())):
    return {"id": user.id, "username": user.username}
```

That's it. You now have:

- `POST /auth/login` — username + password → access & refresh tokens
- `POST /auth/refresh` — refresh token → new token pair
- `POST /auth/logout` — revoke current token
- `POST /auth/logout-all` — revoke all tokens for a user
- `GET /me` — protected route returning the current user

## Test It

Start the server:

```bash
uvicorn app:app --reload
```

Login:

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret"}'
```

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer"
}
```

Access a protected route:

```bash
curl http://localhost:8000/me \
  -H "Authorization: Bearer eyJ..."
```

```json
{
  "id": "1",
  "username": "alice"
}
```

## Recap

- Your user model just needs `id` and `is_active` — no base class.
- `UserBackend` is a protocol with three async methods: `get_by_id`, `get_by_username`, `verify_password`.
- `FastAPIAuth` wires everything together. Call `password_auth_router()` to get login/refresh/logout endpoints.
- `auth.current_user()` returns a FastAPI dependency that resolves the authenticated user from the JWT.

**Next:** [Protecting Routes →](protecting-routes.md)
