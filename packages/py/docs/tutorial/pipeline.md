# Pipeline

The `Pipeline` is a single declarative configuration for your entire auth setup -- strategies, login methods, MFA, password reset, and account linking. Define it once, and `auth.auto_router()` generates all the routes automatically.

## The Pipeline Concept

Instead of manually wiring routers for each feature (password login, OAuth, refresh, logout, MFA, etc.), you declare what you want in one place:

```python
from urauth.pipeline import Pipeline, JWTStrategy, OAuthLogin, Google, MFAMethod

pipeline = Pipeline(
    strategy=JWTStrategy(refresh=True, revocable=True),
    password=True,
    oauth=OAuthLogin(providers=[
        Google(client_id="...", client_secret="..."),
    ]),
    mfa=[MFAMethod(method="otp", required=False)],
    password_reset=True,
    account_linking=True,
)
```

Then pass it to `Auth`, wrap in `FastAuth`, and call `auto_router()`:

```python
from urauth.auth import Auth
from urauth.config import AuthConfig
from urauth.fastapi.auth import FastAuth

core = MyAuth(config=AuthConfig(secret_key="..."), pipeline=pipeline)
auth = FastAuth(core)

app.include_router(auth.auto_router())
```

That single call generates every endpoint your pipeline needs -- login, refresh, logout, OAuth redirects and callbacks, MFA enrollment and verification, password reset flows, and account linking.

## Strategy Selection

The strategy determines how authenticated state is maintained per request. Set it with the `strategy` parameter.

### JWTStrategy (default)

Stateless JWT-based authentication. Tokens are sent via bearer header, cookie, or both.

```python
from urauth.pipeline import JWTStrategy

Pipeline(
    strategy=JWTStrategy(
        refresh=True,       # Enable refresh token rotation (default)
        revocable=True,     # Check token blocklist on each request (default)
        transport="bearer", # "bearer", "cookie", or "hybrid"
    ),
    ...
)
```

| Transport | How tokens are sent |
|-----------|---------------------|
| `"bearer"` | `Authorization: Bearer <token>` header (default) |
| `"cookie"` | HTTP-only cookie, with optional CSRF protection |
| `"hybrid"` | Try bearer header first, fall back to cookie |

### SessionStrategy

Server-side sessions. The session ID is stored in an HTTP-only cookie, and session data lives in a `SessionStore` (in-memory or Redis).

```python
from urauth.pipeline import SessionStrategy

Pipeline(
    strategy=SessionStrategy(cookie_name="session_id"),
    ...
)
```

Requires a `session_store` on the `Auth` instance:

```python
from urauth.backends.memory import MemorySessionStore

core = MyAuth(
    config=config,
    session_store=MemorySessionStore(),
    pipeline=Pipeline(strategy=SessionStrategy(), password=True),
)
```

### BasicAuthStrategy

HTTP Basic authentication -- the user re-authenticates on every request. Useful for simple APIs and machine-to-machine communication.

```python
from urauth.pipeline import BasicAuthStrategy

Pipeline(
    strategy=BasicAuthStrategy(realm="Restricted"),
    ...
)
```

### APIKeyStrategy

API key authentication via a custom header or query parameter.

```python
from urauth.pipeline import APIKeyStrategy

Pipeline(
    strategy=APIKeyStrategy(
        header_name="X-API-Key",   # default
        query_param=None,          # set to "api_key" to also accept query params
    ),
    ...
)
```

Requires overriding `get_user_by_api_key(key)` on your `Auth` subclass.

### FallbackStrategy

Try multiple strategies in order until one succeeds. Useful when your API supports both JWT and API key authentication.

```python
from urauth.pipeline import FallbackStrategy, JWTStrategy, APIKeyStrategy

Pipeline(
    strategy=FallbackStrategy(strategies=[
        JWTStrategy(),
        APIKeyStrategy(header_name="X-API-Key"),
    ]),
    ...
)
```

## Login Methods

Login methods determine how users initially prove their identity.

### Password

The simplest option. Set `password=True` to enable username/password login:

```python
Pipeline(password=True, ...)
```

Requires overriding `get_user_by_username()` and `verify_password()` on your `Auth` subclass.

### OAuth / Social Login

Add OAuth providers to enable social login:

```python
from urauth.pipeline import OAuthLogin, Google, GitHub

Pipeline(
    oauth=OAuthLogin(
        providers=[
            Google(client_id="...", client_secret="..."),
            GitHub(client_id="...", client_secret="..."),
        ],
        callback_path="/auth/oauth/{provider}/callback",  # default
    ),
    ...
)
```

Requires overriding `get_or_create_oauth_user(info)` on your `Auth` subclass. See [OAuth2 & Social Login](oauth2-social-login.md) for details.

### Magic Link

Passwordless login via email link:

```python
from urauth.pipeline import MagicLinkLogin

Pipeline(
    magic_link=MagicLinkLogin(token_ttl=600),  # 10 minutes
    ...
)
```

Requires overriding `send_magic_link(email, token, link)` and `verify_magic_link_token(token)`.

### OTP (One-Time Password)

Time-based or code-based one-time passwords:

```python
from urauth.pipeline import OTPLogin

Pipeline(
    otp=OTPLogin(
        code_type="numeric",      # "numeric", "alpha", or "alphanumeric"
        digits=6,
        period=30,                # validity window in seconds
        issuer_name="MyApp",      # shown in authenticator apps
    ),
    ...
)
```

Requires overriding `verify_otp(user, code)`.

### Passkey (WebAuthn)

FIDO2/WebAuthn passkey authentication:

```python
from urauth.pipeline import PasskeyLogin

Pipeline(
    passkey=PasskeyLogin(
        rp_name="MyApp",
        rp_id=None,  # defaults to request host
    ),
    ...
)
```

Or simply `passkey=True` for defaults. Requires overriding `create_passkey_challenge()`, `verify_passkey_registration()`, and `verify_passkey_assertion()`.

## MFA (Multi-Factor Authentication)

Add a second factor after the primary login:

```python
from urauth.pipeline import MFAMethod

Pipeline(
    password=True,
    mfa=[
        MFAMethod(method="otp", required=False),
        MFAMethod(method="passkey"),
    ],
    ...
)
```

Each `MFAMethod` configures a single MFA method independently:

| Parameter | Description |
|-----------|-------------|
| `method` | The MFA method type: `"otp"` or `"passkey"` |
| `required` | If `True`, all users must complete this method. If `False` (default), only enrolled users are prompted |
| `grace_period` | Seconds after a fresh login before this method is required again. `0` means always required |

Requires overriding `is_mfa_enrolled(user)`, `enroll_mfa(user, method)`, and `verify_mfa(user, method, code)`.

## Password Reset

Enable the 3-step password reset flow:

```python
Pipeline(
    password_reset=True,  # use defaults
    ...
)
```

Or customize the timing:

```python
from urauth.pipeline import PasswordReset

Pipeline(
    password_reset=PasswordReset(
        token_ttl=3600,           # reset token valid for 1 hour
        reset_session_ttl=600,    # 10 minutes to set new password after confirmation
    ),
    ...
)
```

The 3-step flow:

1. **Forgot** -- `POST /password/forgot` sends a reset email with a token
2. **Confirm** -- `POST /password/reset/confirm` validates the token and invalidates the old password immediately
3. **Complete** -- `POST /password/reset/complete` sets the new password using the `reset_session` from step 2

Requires overriding `create_reset_token(user)`, `send_reset_email(email, token, link)`, `validate_reset_token(token)`, `invalidate_password(user)`, and `set_password(user, new_password)`.

## Account Linking

Allow users to connect and disconnect OAuth providers, phone numbers, and email addresses:

```python
Pipeline(
    account_linking=True,
    ...
)
```

Requires overriding `link_oauth(user, info)`, `unlink_oauth(user, provider)`, and `get_linked_accounts(user)`. Optionally override `link_phone(user, phone)` and `link_email(user, email)`.

## Identifiers

Control which identifiers users can log in with. When multiple are enabled, the login endpoint accepts an `identifier` field instead of `username`:

```python
from urauth.pipeline import Identifiers

Pipeline(
    identifiers=Identifiers(
        email=True,      # default
        phone=True,
        username=True,
    ),
    ...
)
```

When `phone` or `username` is enabled alongside `email`, override `get_user_by_identifier(identifier)` on your `Auth` subclass to resolve the user from any of the enabled identifiers.

## auto_router()

Once the pipeline is configured, `auth.auto_router()` generates all routes:

```python
from fastapi import FastAPI

app = FastAPI()
app.include_router(auth.auto_router())
```

The generated routes depend on your pipeline configuration:

| Pipeline setting | Generated routes |
|------------------|------------------|
| `password=True` | `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all` |
| `oauth=OAuthLogin(...)` | `GET /auth/oauth/{provider}/login`, `GET /auth/oauth/{provider}/callback` |
| `magic_link=MagicLinkLogin()` | `POST /auth/magic-link/send`, `POST /auth/magic-link/verify` |
| `otp=OTPLogin()` | `POST /auth/otp/verify` |
| `passkey=True` | `POST /auth/passkey/challenge`, `POST /auth/passkey/register`, `POST /auth/passkey/login` |
| `mfa=[MFAMethod(...)]` | `POST /auth/mfa/enroll`, `POST /auth/mfa/verify` |
| `password_reset=True` | `POST /password/forgot`, `POST /password/reset/confirm`, `POST /password/reset/complete` |
| `account_linking=True` | `POST /auth/link/{provider}`, `DELETE /auth/link/{provider}`, `GET /auth/linked-accounts` |

## Auth Hook Reference

Each pipeline feature maps to specific `Auth` methods you need to override:

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
| API key strategy | `get_user_by_api_key` |
| Multiple identifiers | `get_user_by_identifier` |
| Roles/permissions | `get_user_roles`, `get_user_permissions` |
| Relations | `get_user_relations`, `check_relation` |

## Full Example: SaaS App

A comprehensive example with password login, Google OAuth, OTP-based MFA, and password reset:

```python
from dataclasses import dataclass, field
from uuid import uuid4

from fastapi import Depends, FastAPI

from urauth.auth import Auth
from urauth.authn.password import PasswordHasher
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.auth import FastAuth
from urauth.pipeline import (
    Google,
    Identifiers,
    MFAMethod,
    OAuthLogin,
    Pipeline,
    JWTStrategy,
)

# ── User model ──────────────────────────────────────────────

hasher = PasswordHasher()

@dataclass
class User:
    id: str
    email: str
    hashed_password: str
    is_active: bool = True
    roles: list[str] = field(default_factory=list)
    mfa_secret: str | None = None
    oauth_providers: list[dict] = field(default_factory=list)

USERS: dict[str, User] = {}

# ── Auth subclass ───────────────────────────────────────────

class MyAuth(Auth):
    async def get_user(self, user_id):
        return next((u for u in USERS.values() if u.id == user_id), None)

    async def get_user_by_username(self, username):
        return USERS.get(username)

    async def verify_password(self, user, password):
        return hasher.verify(password, user.hashed_password)

    async def get_or_create_oauth_user(self, info):
        user = USERS.get(info.email)
        if user is None:
            user = User(
                id=str(uuid4()),
                email=info.email,
                hashed_password="",
                is_active=True,
            )
            USERS[info.email] = user
        return user

    # MFA hooks
    async def is_mfa_enrolled(self, user):
        return user.mfa_secret is not None

    async def enroll_mfa(self, user, method):
        import secrets
        secret = secrets.token_hex(20)
        user.mfa_secret = secret
        return {"secret": secret, "method": method}

    async def verify_mfa(self, user, method, code):
        # In production, use pyotp to verify TOTP codes
        return code == "123456"  # placeholder

    # Password reset hooks
    async def create_reset_token(self, user):
        import secrets
        return secrets.token_urlsafe(32)

    async def send_reset_email(self, email, token, link):
        print(f"Reset link for {email}: {link}")

    async def validate_reset_token(self, token):
        # In production, look up token in DB
        return USERS.get("alice@example.com")

    async def invalidate_password(self, user):
        user.hashed_password = ""

    async def set_password(self, user, new_password):
        user.hashed_password = hasher.hash(new_password)


# ── Pipeline ────────────────────────────────────────────────

pipeline = Pipeline(
    strategy=JWTStrategy(refresh=True, revocable=True, transport="bearer"),
    password=True,
    oauth=OAuthLogin(providers=[
        Google(client_id="your-client-id", client_secret="your-client-secret"),
    ]),
    mfa=[MFAMethod(method="otp", required=False)],
    password_reset=True,
    account_linking=True,
    identifiers=Identifiers(email=True),
)

# ── App ─────────────────────────────────────────────────────

config = AuthConfig(secret_key="super-secret-key")
core = MyAuth(config=config, token_store=MemoryTokenStore(), pipeline=pipeline)
auth = FastAuth(core)

app = FastAPI()
app.include_router(auth.auto_router())


@app.get("/me")
async def me(ctx=Depends(auth.context)):
    return {"id": ctx.user.id, "email": ctx.user.email}
```

## Recap

- `Pipeline` is a single declarative config for all auth behavior.
- Choose a **strategy** (JWT, session, basic, API key, or fallback) to control how auth state is maintained.
- Enable **login methods** (password, OAuth, magic link, OTP, passkey) by setting the corresponding fields.
- Add **MFA** for second-factor verification after primary login.
- Enable **password reset** for the 3-step forgot/confirm/complete flow.
- Enable **account linking** to let users connect multiple OAuth providers.
- `auth.auto_router()` generates all routes from the pipeline configuration.
- Override the corresponding `Auth` methods for each feature you enable.

**Next:** [OAuth2 & Social Login](oauth2-social-login.md)
