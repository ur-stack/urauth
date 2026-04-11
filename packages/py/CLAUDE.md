# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

All commands use `uv` as the package manager. Run from the `packages/py` directory.

```bash
make install          # Install all deps (uv sync --all-extras)
make test             # Run tests (uv run pytest)
make check            # Lint + typecheck combined
make lint             # Ruff linter
make lint-fix         # Auto-fix lint issues
make format           # Ruff formatter
make typecheck        # basedpyright (standard mode)
make test-cov         # Tests with coverage report
```

Run a single test file or test:
```bash
uv run pytest tests/core/test_rbac.py
uv run pytest tests/core/test_rbac.py::test_function_name -v
```

Run the FastAPI example app:
```bash
make example-fastapi  # uvicorn on :8000
```

## Architecture

**urauth** is a framework-agnostic Python auth library with a FastAPI adapter. The core package (`src/urauth/`) has no framework dependency; framework-specific code lives in adapter subpackages.

### Layer structure

1. **Core layer** (`src/urauth/`) — Framework-agnostic auth primitives:
   - `auth.py` — `Auth(UserDataMixin)` class with flat constructor (`secret_key=`, `algorithm=`, `method=`, `password=`, `namespace=`, plus all 12 user-data hook callables). Exposes endpoint methods: `login()`, `refresh_tokens()`, `logout()`, `forgot_password()`, `reset_password_*()`, `mfa_*()`, etc. Supports both sync and async overrides via `maybe_await()`.
   - `_async.py` — `maybe_await()` and `run_sync()` helpers (imported by `auth.py` and `users.py`).
   - `users.py` — `UserDataMixin` base for user data access. Supports three patterns: (1) subclass Auth and override methods, (2) mixin composition `class MyAuth(Auth, SQLAlchemyUserStore)`, (3) pass callables to `Auth(get_user=..., ...)`. All 12 hooks are async with sensible defaults.
   - `methods.py` — Auth method configs and login method configs:
     - **Auth methods** (`method=`): `JWT` (with `ttl`, `refresh_ttl`, `store` for token store), `Session`, `BasicAuth`, `APIKey`, `Fallback`
     - **Login methods**: `Password`, `ResetablePassword`, `OAuth`, `MagicLink`, `OTP`, `TOTP`, `Passkey`, `MFA`
   - `results.py` — Framework-agnostic return types for Auth endpoint methods: `AuthResult`, `MFARequiredResult`, `ResetSessionResult`, `MessageResult`
   - `config.py` — Internal `AuthConfig` (still used by TokenLifecycle, kept for backward compat). Users no longer pass `AuthConfig` directly — flat kwargs on `Auth()` instead.
   - `context.py` — `AuthContext` is the single identity model: holds user, roles, permissions, relations, scopes, token, request
   - `tokens/` — `TokenService` for JWT creation/validation via PyJWT
   - `authn/` — Password hashing (bcrypt), OAuth2 client
   - `authz/` — Authorization system (see below)
   - `backends/` — Protocols for user/token/session storage
   - `sessions/` — Redis session store (in-memory session store lives in `backends/memory.py`)

2. **FastAPI adapter** (`src/urauth/fastapi/`) — Single entry point: `FastAuth`
   - `auth.py` — `FastAuth` wraps core `Auth`, reads `Auth.method` directly. Provides `context()`, `current_user`, `require()`, `access_control()` as FastAPI Depends.
   - `routes.py` — `RouterBuilder` (replaces old `PipelineRouterBuilder`). `auto_router()` on FastAuth delegates here.
   - `resolvers.py` — Strategy resolvers (moved from the deleted `pipeline/` directory)
   - `_guards.py` — Consolidated guard base class (`_BaseGuard`) for dual-use decorator/Depends pattern
   - `_utils.py` — Shared helpers (`find_request_param`, `find_context_and_request`)
   - `transport/` — Pluggable token extraction (bearer, cookie, header, hybrid)
   - `authz/access.py` — `AccessControl` with `guard()` for checker-based authorization
   - `middleware.py` — CSRF and token refresh middleware

### Authorization system (`src/urauth/authz/`)

The authz system uses composable primitives with `AuthContext` as the single identity model:
- **Primitives** (`primitives.py`): `Action`, `Resource`, `Permission`, `Role`, `Relation`, `Requirement` — all support `&` (AND) and `|` (OR) composition. Also contains `match_permission()` — the single shared function for wildcard permission matching, used by both `AuthContext` and all checkers.
- **Checkers** (`checker.py`): `PermissionChecker` protocol operates on `AuthContext`. Implementations: `StringChecker` (default, wildcard matching), `RoleExpandingChecker` (maps roles → permissions via hierarchy)
- **RoleRegistry** (`roles.py`): Defines roles with permissions and inheritance, supports `include()` for composition and `with_loader()` for DB-backed roles
- **PermissionEnum** (`permission_enum.py`): Typed permission enums for static definition

### Usage pattern

Three patterns for wiring user data access (all sync/async-transparent):

**Subclass** (recommended)::
```python
from urauth import Auth, JWT, Password
from urauth.backends.memory import MemoryTokenStore
from urauth.fastapi import FastAuth

class MyAuth(Auth):
    async def get_user(self, user_id): ...
    async def get_user_by_username(self, username): ...
    async def verify_password(self, user, password): ...

core = MyAuth(
    method=JWT(ttl=900, refresh_ttl=604800, store=MemoryTokenStore()),
    secret_key="...",
    password=Password(),
)
auth = FastAuth(core)
```

**Mixin composition** (with contrib stores)::
```python
from urauth import Auth, JWT
from urauth.contrib.sqlalchemy import SQLAlchemyUserStore

class MyAuth(Auth, SQLAlchemyUserStore):
    pass

core = MyAuth(
    session_factory=async_session_factory,
    user_model=User,
    method=JWT(...), secret_key="...",
)
auth = FastAuth(core)
```

**Callable kwargs** (quick)::
```python
core = Auth(
    get_user=lambda uid: USERS_DB.get(str(uid)),
    get_user_by_username=lambda u: ...,
    verify_password=lambda user, pw: ...,
    method=JWT(...), secret_key="...",
)
auth = FastAuth(core)
```

Guards and access control are the same regardless of which pattern you use:
```python
access = auth.access_control(registry=registry)

@auth.require(can_read)                           # Requirement-based guard
@access.guard(Perms.TASK_READ)                    # Checker-based guard
ctx: AuthContext = Depends(auth.context)           # Full context
user = Depends(auth.current_user)                 # User object only
```

### Key patterns

- **Single identity model**: `AuthContext` is used everywhere — guards, checkers, and user code. No separate `Subject` type.
- **Single context resolution**: `FastAuth.context()` is the one path for token extraction → validation → user loading → context building. Cached on `request.state._auth_context`.
- **Protocol-driven**: Backends, transports, and checkers are all Protocol-based for pluggability
- **Dual-use guards**: All guards work as `@decorator` and `Depends(guard)` via `_BaseGuard`
- **Composable requirements**: `(user_read & admin) | (task_write & member_of)` builds complex auth rules
- **Flat config**: No more `AuthConfig` object — pass `secret_key`, `algorithm`, etc. directly to `Auth()`
- **User data access**: Three patterns — subclass Auth, mixin composition (`class MyAuth(Auth, SQLAlchemyUserStore)`), or callable kwargs. Subclass overrides take priority over callable kwargs (MRO-based).
- **Namespace isolation**: `namespace=` on `Auth` for multi-project separation

## Code style

- Line length: 120 characters
- Python target: 3.10+
- Linter/formatter: ruff (rules: E, W, F, I, N, UP, B, SIM, RUF)
- Type checker: basedpyright in strict mode
- FastAPI `Depends` default args are allowed in tests and examples (ruff B008 suppressed)
