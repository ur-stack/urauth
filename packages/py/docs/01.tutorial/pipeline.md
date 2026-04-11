# Auth Configuration

Auth methods and login methods are configured directly on the `Auth` instance as flat parameters. Define your auth method, enable login methods, and `auto_router()` generates all the routes automatically.

## The Configuration Concept

Instead of manually wiring routers for each feature (password login, OAuth, refresh, logout, MFA, etc.), you declare what you want directly on `Auth`:

```python
from urauth import Auth, JWT, Password, OAuth, MFA, Google
from urauth.backends.memory import MemoryTokenStore

core = Auth(
    method=JWT(ttl=900, refresh_ttl=604800, refresh=True, revocable=True, store=MemoryTokenStore()),
    secret_key="...",
    password=Password(),
    oauth=OAuth(providers=[
        Google(client_id="...", client_secret="..."),
    ]),
    mfa=MFA(methods=["otp"]),
    password_reset=True,
    account_linking=True,
)
```

Then wrap in `FastAuth` and call `auto_router()`:

```python
from urauth.fastapi import FastAuth

auth = FastAuth(core)

app.include_router(auth.auto_router())
```

That single call generates every endpoint your configuration needs -- login, refresh, logout, OAuth redirects and callbacks, MFA enrollment and verification, password reset flows, and account linking.

## Auth Methods

The auth method determines how authenticated state is maintained per request. Set it with the `method` parameter.

### JWT (default)

Stateless JWT-based authentication. Tokens are sent via bearer header, cookie, or both.

```python
from urauth import JWT

Auth(
    method=JWT(
        ttl=900,            # Access token TTL in seconds (15 min)
        refresh_ttl=604800, # Refresh token TTL in seconds (7 days)
        refresh=True,       # Enable refresh token rotation (default)
        revocable=True,     # Check token blocklist on each request (default)
        store=token_store,  # Token store for revocation tracking
    ),
    secret_key="...",
    ...
)
```

### Session

Server-side sessions. The session ID is stored in an HTTP-only cookie, and session data lives in a session store (in-memory or Redis).

```python
from urauth import Session

Auth(
    method=Session(cookie_name="sid", ttl=86400, store=redis_store),
    secret_key="...",
    ...
)
```

### BasicAuth

HTTP Basic authentication -- the user re-authenticates on every request. Useful for simple APIs and machine-to-machine communication.

```python
from urauth import BasicAuth

Auth(
    method=BasicAuth(realm="Restricted"),
    secret_key="...",
    ...
)
```

### APIKey

API key authentication via a custom header or query parameter.

```python
from urauth import APIKey

Auth(
    method=APIKey(
        header_name="X-API-Key",   # default
        query_param=None,          # set to "api_key" to also accept query params
    ),
    secret_key="...",
    ...
)
```

Requires overriding `get_user_by_api_key(key)` on your `Auth` subclass.

### Fallback

Try multiple auth methods in order until one succeeds. Useful when your API supports both JWT and API key authentication.

```python
from urauth import Fallback, JWT, APIKey

Auth(
    method=Fallback(methods=[
        JWT(ttl=900, store=token_store),
        APIKey(header_name="X-API-Key"),
    ]),
    secret_key="...",
    ...
)
```

## Login Methods

Login methods determine how users initially prove their identity. They are passed as flat parameters on `Auth`.

### Password

The simplest option. Pass `password=Password()` to enable username/password login:

```python
from urauth import Password

Auth(method=JWT(...), secret_key="...", password=Password())
```

Requires overriding `get_user_by_username()` and `verify_password()` on your `Auth` subclass.

### OAuth / Social Login

Add OAuth providers to enable social login:

```python
from urauth import OAuth, Google, GitHub

Auth(
    method=JWT(...),
    secret_key="...",
    password=Password(),
    oauth=OAuth(
        providers=[
            Google(client_id="...", client_secret="..."),
            GitHub(client_id="...", client_secret="..."),
        ],
    ),
)
```

Requires overriding `get_or_create_oauth_user(info)` on your `Auth` subclass. See [OAuth2 & Social Login](oauth2-social-login.md) for details.

### Magic Link

Passwordless login via email link:

```python
from urauth import MagicLink

Auth(
    method=JWT(...),
    secret_key="...",
    magic_link=MagicLink(token_ttl=600),  # 10 minutes
)
```

Requires overriding `send_magic_link(email, token, link)` and `verify_magic_link_token(token)`.

### OTP (One-Time Password)

Time-based or code-based one-time passwords with pluggable send/verify functions:

```python
from urauth import OTP

Auth(
    method=JWT(...),
    secret_key="...",
    otp=OTP(
        send=my_send_fn,     # Pluggable OTP sender
        verify=my_verify_fn, # Pluggable OTP verifier
        digits=6,
        ttl=300,             # OTP validity window in seconds
    ),
)
```

### Passkey (WebAuthn)

FIDO2/WebAuthn passkey authentication:

```python
from urauth import Passkey

Auth(
    method=JWT(...),
    secret_key="...",
    passkey=Passkey(
        rp_name="MyApp",
        rp_id=None,  # defaults to request host
    ),
)
```

Or simply `passkey=True` for defaults. Requires overriding `create_passkey_challenge()`, `verify_passkey_registration()`, and `verify_passkey_assertion()`.

## MFA (Multi-Factor Authentication)

Add a second factor after the primary login:

```python
from urauth import MFA

Auth(
    method=JWT(...),
    secret_key="...",
    password=Password(),
    mfa=MFA(methods=["otp", "passkey"]),
)
```

`MFA` configures multi-factor authentication with a list of supported methods. Requires overriding `is_mfa_enrolled(user)`, `enroll_mfa(user, method)`, and `verify_mfa(user, method, code)`.

## Password Reset

Enable the password reset flow:

```python
Auth(
    method=JWT(...),
    secret_key="...",
    password=Password(),
    password_reset=True,  # use defaults
)
```

Or customize with `ResetablePassword` for more control:

```python
from urauth import ResetablePassword, OTP

Auth(
    method=JWT(...),
    secret_key="...",
    password=ResetablePassword(
        reset_token_ttl=3600,           # reset token valid for 1 hour
        verification=OTP(send=otp_phone_send, verify=otp_phone_verify),  # OTP verification in reset flow
    ),
)
```

The reset flow:

1. **Forgot** -- `POST /password/forgot` sends a reset email with a token
2. **Confirm** -- `POST /password/reset/confirm` validates the token and invalidates the old password immediately
3. **Complete** -- `POST /password/reset/complete` sets the new password using the `reset_session` from step 2

Requires overriding `create_reset_token(user)`, `send_reset_email(email, token, link)`, `validate_reset_token(token)`, `invalidate_password(user)`, and `set_password(user, new_password)`.

## Account Linking

Allow users to connect and disconnect OAuth providers, phone numbers, and email addresses:

```python
Auth(
    method=JWT(...),
    secret_key="...",
    account_linking=True,
)
```

Requires overriding `link_oauth(user, info)`, `unlink_oauth(user, provider)`, and `get_linked_accounts(user)`. Optionally override `link_phone(user, phone)` and `link_email(user, email)`.

## Identifiers

Control which identifiers users can log in with. When multiple are enabled, the login endpoint accepts an `identifier` field instead of `username`:

```python
from urauth import Identifiers

Auth(
    method=JWT(...),
    secret_key="...",
    password=Password(),
    identifiers=Identifiers(
        email=True,      # default
        phone=True,
        username=True,
    ),
)
```

When `phone` or `username` is enabled alongside `email`, override `get_user_by_identifier(identifier)` on your `Auth` subclass to resolve the user from any of the enabled identifiers.

## auto_router()

Once the auth instance is configured, `auth.auto_router()` generates all routes:

```python
from fastapi import FastAPI

app = FastAPI()
app.include_router(auth.auto_router())
```

The generated routes depend on your configuration:

| Configuration | Generated routes |
|---------------|------------------|
| `password=Password()` | `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all` |
| `oauth=OAuth(...)` | `GET /auth/oauth/{provider}/login`, `GET /auth/oauth/{provider}/callback` |
| `magic_link=MagicLink()` | `POST /auth/magic-link/send`, `POST /auth/magic-link/verify` |
| `otp=OTP()` | `POST /auth/otp/verify` |
| `passkey=True` | `POST /auth/passkey/challenge`, `POST /auth/passkey/register`, `POST /auth/passkey/login` |
| `mfa=MFA(...)` | `POST /auth/mfa/enroll`, `POST /auth/mfa/verify` |
| `password_reset=True` | `POST /password/forgot`, `POST /password/reset/confirm`, `POST /password/reset/complete` |
| `account_linking=True` | `POST /auth/link/{provider}`, `DELETE /auth/link/{provider}`, `GET /auth/linked-accounts` |

## Auth Endpoint Methods

The `Auth` instance exposes endpoint methods that power the generated routes. You can also call them directly for custom flows:

- `auth.login()` -- authenticate a user and return an `AuthResult`
- `auth.refresh_tokens()` -- refresh a token pair
- `auth.logout()` -- revoke the current session
- `auth.forgot_password()` -- initiate password reset
- `auth.reset_password_confirm()` -- validate reset token
- `auth.reset_password_complete()` -- set new password
- `auth.mfa_enroll()` -- enroll in MFA
- `auth.mfa_verify()` -- verify MFA code

These methods return result types from `urauth.results`: `AuthResult`, `MFARequiredResult`, `ResetSessionResult`, `MessageResult`.

## Auth Subclass Hook Reference

Each feature maps to specific `Auth` subclass methods you need to override:

| Feature | Required overrides |
|---------|-------------------|
| Password login | `get_user`, `get_user_by_username`, `verify_password` |
| OAuth | `get_user`, `get_or_create_oauth_user` |
| Magic link | `get_user`, `send_magic_link`, `verify_magic_link_token` |
| OTP login | `get_user`, `verify_otp` |
| Passkey login | `get_user`, `create_passkey_challenge`, `verify_passkey_registration`, `verify_passkey_assertion` |
| MFA | `is_mfa_enrolled`, `enroll_mfa`, `verify_mfa` |
| Password reset | `get_user_by_username`, `create_reset_token`, `send_reset_email`, `validate_reset_token`, `invalidate_password`, `set_password` |
| Account linking | `link_oauth`, `unlink_oauth`, `get_linked_accounts` |
| API key method | `get_user_by_api_key` |
| Multiple identifiers | `get_user_by_identifier` |
| Roles/permissions | `get_user_roles`, `get_user_permissions` |
| Relations | `get_user_relations`, `check_relation` |

## Full Example: SaaS App

A comprehensive example with password login, Google OAuth, OTP-based MFA, and password reset.

::: info Required packages
```bash
pip install "urauth[fastapi]" sqlmodel aiosqlite pyotp
```
:::

```python
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pyotp
from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import Field, SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from urauth import Auth, JWT, MFA, OAuth, Password, PasswordHasher, Google, Identifiers
from urauth.backends.memory import MemoryTokenStore
from urauth.contrib.sqlmodel import SQLModelUserStore
from urauth.fastapi import FastAuth

# ── Database ────────────────────────────────────────────────

DATABASE_URL = "sqlite+aiosqlite:///./app.db"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ── User model ──────────────────────────────────────────────

hasher = PasswordHasher()


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str = ""
    is_active: bool = True
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    mfa_secret: str | None = None


# ── Auth subclass ────────────────────────────────────────────

class MyAuth(Auth, SQLModelUserStore):
    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

    async def get_or_create_oauth_user(self, info):
        async with async_session() as session:
            result = await session.exec(select(User).where(User.email == info.email))
            user = result.first()
            if user is None:
                user = User(email=info.email)
                session.add(user)
                await session.commit()
                await session.refresh(user)
            return user

    # MFA hooks
    async def is_mfa_enrolled(self, user):
        return user.mfa_secret is not None

    async def enroll_mfa(self, user, method):
        secret = pyotp.random_base32()
        async with async_session() as session:
            db_user = await session.get(User, user.id)
            db_user.mfa_secret = secret
            await session.commit()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(user.email, issuer_name="MyApp")
        return {"secret": secret, "totp_uri": totp_uri, "method": method}

    async def verify_mfa(self, user, method, code):
        if user.mfa_secret is None:
            return False
        return pyotp.TOTP(user.mfa_secret).verify(code)

    # Password reset hooks
    async def create_reset_token(self, user):
        # In production, persist this token in a reset_tokens table with an expiry
        return secrets.token_urlsafe(32)

    async def send_reset_email(self, email, token, link):
        # In production, send via your email provider (e.g. SendGrid, SES)
        print(f"Reset link for {email}: {link}")

    async def validate_reset_token(self, token):
        # In production, look up token in DB, check expiry, return associated user
        async with async_session() as session:
            result = await session.exec(select(User).where(User.email == "alice@example.com"))
            return result.first()

    async def invalidate_password(self, user):
        async with async_session() as session:
            db_user = await session.get(User, user.id)
            db_user.hashed_password = ""
            await session.commit()

    async def set_password(self, user, new_password):
        async with async_session() as session:
            db_user = await session.get(User, user.id)
            db_user.hashed_password = hasher.hash(new_password)
            await session.commit()


# ── Auth configuration ─────────────────────────────────────

core = MyAuth(
    session_factory=async_session,
    user_model=User,
    method=JWT(ttl=900, refresh_ttl=604800, refresh=True, revocable=True, store=MemoryTokenStore()),
    secret_key="super-secret-key",
    password=Password(),
    oauth=OAuth(providers=[
        Google(client_id="your-client-id", client_secret="your-client-secret"),
    ]),
    mfa=MFA(methods=["otp"]),
    password_reset=True,
    account_linking=True,
    identifiers=Identifiers(email=True),
)

# ── App ─────────────────────────────────────────────────────

auth = FastAuth(core)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(auth.auto_router())


@app.get("/me")
async def me(ctx=Depends(auth.context)):
    return {"id": str(ctx.user.id), "email": ctx.user.email}
```

## Recap

- Auth methods and login methods are configured directly on the `Auth` instance as flat parameters.
- Choose an **auth method** (`JWT`, `Session`, `BasicAuth`, `APIKey`, or `Fallback`) to control how auth state is maintained.
- Enable **login methods** (`Password`, `OAuth`, `MagicLink`, `OTP`, `Passkey`) by passing them as parameters.
- Add **MFA** with `MFA(methods=[...])` for second-factor verification after primary login.
- Enable **password reset** with `password_reset=True` or `ResetablePassword(...)` for the forgot/confirm/complete flow.
- Enable **account linking** to let users connect multiple OAuth providers.
- `auth.auto_router()` generates all routes from the configuration.
- Override the corresponding methods on your `Auth` subclass for each feature you enable.

**Next:** [OAuth2 & Social Login](oauth2-social-login.md)
