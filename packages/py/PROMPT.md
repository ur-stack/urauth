# urauth Python Library — Complete Refactoring

You are refactoring `urauth`, a framework-agnostic Python auth library with a FastAPI adapter,
located at `/Users/grandmagus/Documents/Projects/fastapi-pkgs/urauth/packages/py`.

The goal: transform this from a working alpha into a **clean, production-grade auth library**
that developers trust and enjoy using. Every line should justify its existence. The API should
be obvious, the internals simple, and the docs precise.

Read CLAUDE.md first, then read every file under `src/urauth/` before making any changes.

---

## Guiding Principles

1. **Simplicity over flexibility** — Remove abstractions that serve hypothetical users. If only
   one concrete implementation exists for a protocol, inline it or simplify.
2. **Single way to do things** — Where two mechanisms solve the same problem, pick the better
   one and remove the other.
3. **Narrow interfaces** — Classes should have 3-7 public methods, not 30. Wide interfaces are
   hard to implement, test, and document.
4. **Async-first** — The core should be async. Sync wrappers belong in adapters or a thin
   compatibility layer, not scattered throughout.
5. **Composition over inheritance** — Prefer passing collaborators over subclassing. Mixins
   and deep hierarchies make code hard to follow.
6. **No dead code** — If flask/ and django/ adapters are stubs, remove them entirely. Ship
   what works.
7. **Security by default** — Secure defaults for every config value. No footguns in the
   happy path.

---

## Phase 1: Audit and Remove

### 1.1 — Remove dead/stub code
- Delete `src/urauth/flask/` and `src/urauth/django/` if they're empty stubs.
- Remove any classes, methods, or parameters that have zero usage in tests or examples.
- Delete commented-out code, TODO placeholders for unimplemented features, and any
  `NotImplementedError` stubs that aren't part of an abstract interface.

### 1.2 — Consolidate duplicate logic
- **Permission matching** is duplicated across `AuthContext.has_permission()`,
  `StringChecker.has_permission()`, and `RoleExpandingChecker`. Extract the wildcard
  matching logic into a single shared function (e.g., `match_permission(pattern, target) -> bool`).
- **Dual-use guard logic** exists in both `_guards.py` (`_BaseGuard`) and
  `fastapi/authz/access.py` (`_Guard`). Unify into one base implementation.
  Both do: signature inspection, parameter injection, decorator wrapping, `__call__`
  for Depends. One class should handle this.
- **Sync/async bridging** — `maybe_await()`, `run_sync()`, and the `_sync` method
  variants on `Auth` add ~100 lines of complexity. Decide: keep core async-only and
  provide a `SyncAuth` wrapper, OR keep the bridge but centralize it in one place
  (a single `_compat.py` module).

### 1.3 — Simplify exception hierarchy
- `AuthError` has 5+ subclasses that only differ by `status_code`. Evaluate whether
  these warrant separate classes or can be reduced to:
  ```python
  class AuthError(Exception):
      def __init__(self, detail: str, status_code: int = 401): ...

  # Keep only truly distinct behaviors:
  class UnauthorizedError(AuthError): ...  # 401
  class ForbiddenError(AuthError): ...     # 403
  ```
  Token-specific errors (expired, revoked, invalid) can be `UnauthorizedError` with
  different messages unless callers need to `except` them distinctly.

---

## Phase 2: Simplify Core Architecture

### 2.1 — Narrow the `Auth` base class
The current `Auth` class has 30+ overridable methods (get_user, verify_password,
get_user_roles, get_user_permissions, handle_magic_link, verify_otp, handle_passkey,
get_mfa_secret, reset_password, link_account, etc.).

**Refactor approach:**
- Keep `Auth` as a minimal base with only the essential methods that ALL auth
  implementations need (3-5 methods max):
  ```python
  class Auth:
      async def get_user(self, user_id: str) -> Any | None: ...
      async def get_user_by_username(self, username: str) -> Any | None: ...
      async def verify_password(self, user: Any, password: str) -> bool: ...
      async def get_user_roles(self, user: Any) -> list[str]: ...
      async def get_user_permissions(self, user: Any) -> list[str]: ...
  ```
- Move optional features into **protocol interfaces** that users implement separately:
  ```python
  class OAuthProvider(Protocol):
      async def get_or_create_user(self, provider: str, profile: dict) -> Any: ...

  class MFAProvider(Protocol):
      async def get_mfa_secret(self, user: Any) -> str | None: ...
      async def verify_mfa(self, user: Any, code: str) -> bool: ...

  class PasswordResetProvider(Protocol):
      async def create_reset_token(self, user: Any) -> str: ...
      async def reset_password(self, user: Any, new_password: str) -> None: ...
  ```
- This way, `Auth` is easy to implement for basic cases, and advanced features
  are opt-in via additional protocols — not a massive class to subclass.

### 2.2 — Simplify `AuthContext`
- Review `AuthContext` fields. If any are rarely used or only needed internally,
  remove them from the public model.
- Ensure `AuthContext` is truly immutable (frozen dataclass or model).
- The `satisfies()` method should be the single entry point for requirement checking.
  Remove any other methods that duplicate this logic.

### 2.3 — Clean up authz primitives
- `Action`, `Resource`, `Permission`, `Role`, `Relation`, `Requirement`, `AllOf`, `AnyOf`
  — verify each is actually used. If `Action` and `Resource` are only used to construct
  `Permission` strings, consider whether they need to be separate classes or just
  string helpers.
- The `&` / `|` operator overloading on primitives is clever but ensure it's
  well-tested and the resulting tree is easy to evaluate. Document the DSL clearly.

### 2.4 — Streamline authorization checking
- Currently there's `PermissionChecker` (protocol), `StringChecker`, and
  `RoleExpandingChecker`. Evaluate:
  - Is `StringChecker` ever used without `RoleExpandingChecker`?
  - Can they be merged into one `Checker` class with optional role expansion?
  - Or is the separation genuinely useful?
- `RoleRegistry` mixes static definitions with dynamic loading and caching.
  If the caching adds significant complexity, consider whether it belongs here
  or should be the caller's responsibility.

---

## Phase 3: Simplify FastAPI Adapter

### 3.1 — `FastAuth` as the single entry point
- `FastAuth` should remain the primary API surface. Ensure it has a clean, minimal
  public interface.
- Remove or inline any helper methods that are only called once.
- The `context()` dependency should be the ONE way to get auth context. No alternative
  paths.

### 3.2 — Refactor PipelineRouterBuilder (811 lines)
This is the biggest single file and the most complex class. Options:
- **Option A (preferred):** Break into composable route builders:
  ```python
  class PasswordRoutes:
      def register(self, router: APIRouter, auth: Auth, transport: Transport): ...

  class OAuthRoutes:
      def register(self, router: APIRouter, auth: Auth, oauth: OAuthManager): ...

  class MFARoutes:
      def register(self, router: APIRouter, auth: Auth): ...
  ```
  The Pipeline config then selects which builders to activate.
- **Option B:** Keep monolithic but extract each feature's routes into separate
  private methods that are ≤50 lines each.
- Whichever you choose, each route handler should be ≤30 lines. Extract shared
  logic into helpers.

### 3.3 — Unify guards
- Merge `_BaseGuard` and `AccessControl._Guard` into one mechanism.
- The guard should work as both `@decorator` and `Depends(guard)`.
- Prefer composition: `Guard(checker, requirement)` over inheritance.

### 3.4 — Strategy resolvers
- Replace `isinstance()` dispatch in `build_resolver()` with a registry dict
  or visitor pattern.
- Each resolver is small (~30 lines) — consider if they can be lambda/closures
  instead of full classes.

### 3.5 — Transport layer
- The transport layer (bearer, cookie, header, hybrid) is already clean.
- Minor: `HybridTransport` could be a factory function instead of a class
  if it's just combining two transports.

---

## Phase 4: Code Quality

### 4.1 — Type safety
- Ensure all public methods have complete type annotations.
- Use `TypeVar` and generics for the user type:
  ```python
  UserT = TypeVar("UserT")
  class Auth(Generic[UserT]):
      async def get_user(self, user_id: str) -> UserT | None: ...
  ```
  This eliminates `Any` in the user-facing API and gives downstream code proper
  type inference.
- Run `basedpyright` in strict mode and fix all errors.

### 4.2 — Docstrings
- Every public class and method needs a docstring.
- Use Google-style docstrings consistently.
- Docstrings should say **what** and **why**, not restate the signature.
- Include short usage examples in class-level docstrings for key classes
  (`Auth`, `FastAuth`, `AuthContext`, `RoleRegistry`, `AccessControl`).

### 4.3 — Module-level `__all__`
- Every `__init__.py` should define `__all__` explicitly.
- Only export what users need. Internal helpers stay private.

### 4.4 — Security review
- Verify JWT validation checks `exp`, `iat`, `nbf`, `iss`, `aud` claims properly.
- Ensure token comparison uses constant-time comparison (`hmac.compare_digest`).
- Password hashing: verify bcrypt cost factor is configurable and defaults to ≥12.
- CSRF token generation uses `secrets.token_urlsafe`.
- Cookie settings default to `secure=True`, `httponly=True`, `samesite="lax"`.
- Rate limiter isn't bypassable by header spoofing (X-Forwarded-For).
- Refresh token rotation invalidates old tokens (no replay).
- No secrets in error messages or logs.

---

## Phase 5: Tests

### 5.1 — Fix broken tests
After refactoring, all existing tests will likely need updates. Fix them to match
the new API surface.

### 5.2 — Add missing coverage
- Strategy resolvers (JWT, session, basic, API key)
- OAuth2 flow (at least mock the HTTP calls)
- Session stores (memory and Redis mock)
- Multi-tenant middleware
- Rate limiter edge cases
- Error paths: expired tokens, revoked tokens, missing permissions, invalid
  credentials

### 5.3 — Test organization
- Mirror `src/` structure in `tests/`.
- Each test file should be ≤200 lines. Split large test files by feature.
- Use fixtures for common setup (auth instance, test user, token).

---

## Phase 6: Documentation

### 6.1 — Update docs to match new API
- Every code example in docs must be tested or at minimum syntactically valid.
- Remove docs for features that were deleted or simplified.
- Update the tutorial progression: first-steps → protecting-routes → access-control
  → advanced topics.

### 6.2 — API reference
- Auto-generate from docstrings where possible (mkdocstrings).
- Ensure reference docs cover every public class and function.

### 6.3 — Clean up mkdocs.yml nav
- Remove entries for deleted pages.
- Ensure nav order matches learning progression.

---

## Phase 7: Package & Config

### 7.1 — pyproject.toml
- Review optional dependencies. Remove groups for deleted adapters (flask, django).
- Ensure version constraints are not overly restrictive.
- Add classifiers for PyPI discoverability.

### 7.2 — Exports
- `urauth.__init__` should export a curated, minimal API surface.
- Group exports logically with comments.
- Currently exports ~100 names — target ≤40.

---

## Constraints

- **Do NOT add new dependencies** unless strictly necessary for security
  (e.g., upgrading a crypto library).
- **Do NOT change the public API** without a clear improvement in usability.
  When in doubt, keep backward compatibility and deprecate.
- **Python 3.10+ minimum** — use modern syntax (`X | Y` unions, `match` statements
  where appropriate).
- **Run `make check` and `make test`** after each phase to catch regressions early.
- **Keep commits atomic** — one logical change per commit.

---

## Order of Operations

1. Read everything first. Understand the full picture.
2. Phase 1 (audit/remove) — get rid of dead weight.
3. Phase 2 (simplify core) — narrow interfaces, remove duplication.
4. Phase 3 (simplify FastAPI) — refactor the adapter layer.
5. Phase 4 (code quality) — types, docs, security.
6. Phase 5 (tests) — fix and expand.
7. Phase 6 (documentation) — update to match new code.
8. Phase 7 (packaging) — clean up exports and config.

After each phase, run `make check && make test` and fix any issues before proceeding.

---

## Success Criteria

When done, the library should:
- Have ≤3,500 LOC in `src/` (down from ~5,650)
- Export ≤40 public names (down from ~100)
- Have zero `basedpyright` errors in strict mode
- Have ≥85% test coverage
- Have every public class/method documented with docstrings
- Have no duplicated logic across modules
- Be something a developer can understand by reading `FastAuth` and `Auth` alone
