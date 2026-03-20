# OAuth2 & Social Login

Let users sign in with Google, GitHub, and other providers.

## Install

OAuth support requires the `oauth` extra:

```bash
pip install "fastapi-auth[oauth]"
```

## Register a Provider

```python
auth.register_oauth_provider(
    "google",
    client_id="your-google-client-id",
    client_secret="your-google-client-secret",
)
```

That's it — fastapi-auth ships with pre-configured defaults for common providers (authorization URLs, token URLs, scopes). You just supply your credentials.

## Add the OAuth Router

```python
app.include_router(auth.oauth_router("google"))
```

This creates two endpoints:

- `GET /auth/oauth/google/login` — redirects the user to Google's consent screen
- `GET /auth/oauth/google/callback` — handles the callback, creates/links the user, returns tokens

## The Login Flow

1. Your frontend redirects to `GET /auth/oauth/google/login`
2. The user authenticates with Google
3. Google redirects back to `GET /auth/oauth/google/callback`
4. fastapi-auth receives the OAuth user info
5. The `AccountLinker` matches or creates a local user
6. A JWT token pair is returned

## Account Linking

The `AccountLinker` tries to match OAuth users to existing accounts by **verified email**:

- If an existing user has the same email → link the account
- If no match → call `backend.create_oauth_user(info)` to create a new user

```python
class MyBackend:
    async def get_by_id(self, user_id):
        ...

    async def get_by_username(self, username):
        ...

    async def verify_password(self, user, password):
        ...

    async def create_oauth_user(self, info):  # (1)!
        """Create a new user from OAuth info."""
        user = User(
            id=str(uuid4()),
            username=info.email or info.sub,
            hashed_password="",  # no password for OAuth users
            is_active=True,
            is_verified=info.email_verified,
        )
        USERS[user.username] = user
        return user
```

1. This method is optional. If not implemented, OAuth login only works for users who already exist.

The `OAuthUserInfo` object contains:

| Field | Type | Description |
|-------|------|-------------|
| `provider` | `str` | Provider name (e.g., `"google"`) |
| `sub` | `str` | Provider's unique user ID |
| `email` | `str | None` | User's email |
| `email_verified` | `bool` | Whether the provider verified the email |
| `name` | `str | None` | Display name |
| `picture` | `str | None` | Profile picture URL |
| `raw` | `dict | None` | Full raw response from the provider |

## Supported Providers

fastapi-auth includes pre-configured defaults for:

| Provider | OIDC | Registration |
|----------|------|--------------|
| Google | Yes | `auth.register_oauth_provider("google", ...)` |
| GitHub | No | `auth.register_oauth_provider("github", ...)` |
| Microsoft | Yes | `auth.register_oauth_provider("microsoft", ...)` |
| Apple | Custom | `auth.register_oauth_provider("apple", ...)` |
| Discord | No | `auth.register_oauth_provider("discord", ...)` |
| GitLab | No | `auth.register_oauth_provider("gitlab", ...)` |

## Custom Provider Settings

You can override any default or add custom providers:

```python
auth.register_oauth_provider(
    "github",
    client_id="...",
    client_secret="...",
    authorize_url="https://github.com/login/oauth/authorize",  # (1)!
    scope="user:email read:org",  # (2)!
)
```

1. Override the default authorization URL if needed.
2. Request additional scopes beyond the defaults.

## Multiple Providers

Register and mount as many as you need:

```python
auth.register_oauth_provider("google", client_id="...", client_secret="...")
auth.register_oauth_provider("github", client_id="...", client_secret="...")
auth.register_oauth_provider("discord", client_id="...", client_secret="...")

app.include_router(auth.oauth_router("google"))
app.include_router(auth.oauth_router("github"))
app.include_router(auth.oauth_router("discord"))
```

## Recap

- Install the `oauth` extra.
- `register_oauth_provider()` sets up a provider with your credentials.
- `oauth_router()` adds login/callback endpoints.
- `AccountLinker` matches users by verified email or calls `create_oauth_user()` for new accounts.
- Six providers are pre-configured; supply `client_id` and `client_secret` to use them.

**Next:** [RBAC & Permissions →](rbac-permissions.md)
