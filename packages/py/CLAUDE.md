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
   - `auth.py` — Base `Auth` class supporting both sync and async method overrides (uses `maybe_await()` for transparency). Subclass and override `get_user`, `get_user_by_username`, `verify_password`, `get_user_roles`, etc.
   - `config.py` — `AuthConfig` (pydantic-settings, env prefix `AUTH_`)
   - `context.py` — `AuthContext` is the single identity model: holds user, roles, permissions, relations, scopes, token, request
   - `tokens/` — `TokenService` for JWT creation/validation via PyJWT
   - `authn/` — Password hashing (bcrypt), OAuth2 client
   - `authz/` — Authorization system (see below)
   - `backends/` — Protocols for user/token/session storage
   - `sessions/` — Redis session store (in-memory session store lives in `backends/memory.py`)

2. **FastAPI adapter** (`src/urauth/fastapi/`) — Single entry point: `FastAuth`
   - `auth.py` — `FastAuth` wraps core `Auth`, provides `context()`, `current_user`, `require()`, `access_control()` as FastAPI Depends
   - `_guards.py` — Consolidated guard base class (`_BaseGuard`) for dual-use decorator/Depends pattern
   - `_utils.py` — Shared helpers (`find_request_param`, `find_context_and_request`)
   - `transport/` — Pluggable token extraction (bearer, cookie, header, hybrid)
   - `authz/access.py` — `AccessControl` with `guard()` for checker-based authorization
   - `router.py` — Pre-built login/logout/refresh routes
   - `middleware.py` — CSRF and token refresh middleware

### Authorization system (`src/urauth/authz/`)

The authz system uses composable primitives with `AuthContext` as the single identity model:
- **Primitives** (`primitives.py`): `Action`, `Resource`, `Permission`, `Role`, `Relation`, `Requirement` — all support `&` (AND) and `|` (OR) composition. Also contains `match_permission()` — the single shared function for wildcard permission matching, used by both `AuthContext` and all checkers.
- **Checkers** (`checker.py`): `PermissionChecker` protocol operates on `AuthContext`. Implementations: `StringChecker` (default, wildcard matching), `RoleExpandingChecker` (maps roles → permissions via hierarchy)
- **RoleRegistry** (`roles.py`): Defines roles with permissions and inheritance, supports `include()` for composition and `with_loader()` for DB-backed roles
- **PermissionEnum** (`permission_enum.py`): Typed permission enums for static definition

### FastAuth usage pattern

```python
# 1. Subclass Auth with your user storage
class MyAuth(Auth):
    async def get_user(self, user_id): ...
    async def get_user_by_username(self, username): ...
    async def verify_password(self, user, password): ...

# 2. Wrap in FastAuth
core = MyAuth(config=AuthConfig(...), token_store=MemoryTokenStore())
auth = FastAuth(core)

# 3. Use guards and access control
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

## Code style

- Line length: 120 characters
- Python target: 3.10+
- Linter/formatter: ruff (rules: E, W, F, I, N, UP, B, SIM, RUF)
- Type checker: basedpyright in strict mode
- FastAPI `Depends` default args are allowed in tests and examples (ruff B008 suppressed)
