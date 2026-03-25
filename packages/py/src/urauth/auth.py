"""Framework-agnostic Auth base class.

All overridable methods accept both sync and async implementations::

    class SyncAuth(Auth):
        def get_user(self, user_id):          # sync — works
            return db.users.get(user_id)

    class AsyncAuth(Auth):
        async def get_user(self, user_id):    # async — also works
            return await db.users.get(user_id)
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
from collections.abc import Callable
from typing import Any

from urauth.authz.primitives import Permission, Relation, RelationTuple, Role
from urauth.backends.base import SessionStore, TokenStore
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.context import AuthContext
from urauth.exceptions import UnauthorizedError
from urauth.tenant.hierarchy import TenantPath
from urauth.tokens.lifecycle import TokenLifecycle
from urauth.types import TokenPayload


async def maybe_await(result: Any) -> Any:
    """Await if coroutine, return as-is otherwise."""
    if inspect.isawaitable(result):
        return await result
    return result


def run_sync(coro: Any) -> Any:
    """Run a coroutine synchronously. Works outside and inside event loops."""
    if not inspect.isawaitable(coro):
        return coro
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        return asyncio.run(coro)  # type: ignore[arg-type]

    # Inside a running loop — create a new thread to avoid deadlock
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()  # type: ignore[arg-type]


class Auth:
    """Framework-agnostic auth class.

    Two ways to provide data access:

    **1. Pass callables (no subclassing needed):**

    ::

        auth = Auth(
            config=AuthConfig(...),
            get_user=lambda uid: db.get_user(uid),
            get_user_by_username=lambda name: db.get_by_name(name),
            verify_password=lambda user, pw: hasher.verify(pw, user.hash),
        )

    **2. Subclass and override methods (full control):**

    ::

        class MyAuth(Auth):
            async def get_user(self, user_id): ...
            async def get_user_by_username(self, username): ...
            async def verify_password(self, user, password): ...

    All overridable methods accept both sync and async implementations.
    The framework handles both transparently via ``maybe_await()``.
    """

    # ── Required overrides ─────────────────────────────────────

    def get_user(self, user_id: Any) -> Any | None:
        if self._get_user_fn is not None:
            return self._get_user_fn(user_id)
        raise NotImplementedError("Override get_user() or pass get_user= to Auth()")

    def get_user_by_username(self, username: str) -> Any | None:
        if self._get_user_by_username_fn is not None:
            return self._get_user_by_username_fn(username)
        raise NotImplementedError("Override get_user_by_username() or pass get_user_by_username= to Auth()")

    def verify_password(self, user: Any, password: str) -> bool:
        if self._verify_password_fn is not None:
            return self._verify_password_fn(user, password)
        raise NotImplementedError("Override verify_password() or pass verify_password= to Auth()")

    # ── Authorization overrides (optional) ─────────────────────

    def get_user_roles(self, user: Any) -> list[Role]:
        """Default: reads ``user.roles`` and wraps strings as ``Role(name)``."""
        if self._get_user_roles_fn is not None:
            return self._get_user_roles_fn(user)
        role_names = getattr(user, "roles", [])
        return [Role(name) if isinstance(name, str) else name for name in role_names]

    def get_user_permissions(self, user: Any) -> list[Permission]:
        if self._get_user_permissions_fn is not None:
            return self._get_user_permissions_fn(user)
        return []

    def get_user_relations(self, user: Any) -> list[RelationTuple]:
        return []

    def check_relation(self, user: Any, relation: Relation, resource_id: str) -> bool:
        """Check if user has a specific relation to a resource.

        Default calls ``get_user_relations`` (sync only). Override with async
        if ``get_user_relations`` is async.
        """
        result = self.get_user_relations(user)
        if inspect.isawaitable(result):
            raise RuntimeError(
                "check_relation default impl can't call async get_user_relations. "
                "Override check_relation with an async method."
            )
        return any(rt.relation == relation and rt.object_id == resource_id for rt in result)

    # ── Identifier resolution ──────────────────────────────────

    def get_user_by_identifier(self, identifier: str) -> Any | None:
        """Default falls back to ``get_user_by_username``."""
        return self.get_user_by_username(identifier)

    # ── Magic link hooks ───────────────────────────────────────

    def send_magic_link(self, email: str, token: str, link: str) -> None:
        raise NotImplementedError("Override send_magic_link() to use magic link login")

    def verify_magic_link_token(self, token: str) -> Any | None:
        raise NotImplementedError("Override verify_magic_link_token() to use magic link login")

    # ── OTP hooks ──────────────────────────────────────────────

    def verify_otp(self, user: Any, code: str) -> bool:
        raise NotImplementedError("Override verify_otp() to use OTP login")

    # ── API key hook ───────────────────────────────────────────

    def get_user_by_api_key(self, key: str) -> Any | None:
        raise NotImplementedError("Override get_user_by_api_key() to use API key strategy")

    # ── OAuth hooks ────────────────────────────────────────────

    def get_or_create_oauth_user(self, info: Any) -> Any | None:
        """Default falls back to ``get_user_by_username(info.email)``."""
        email = getattr(info, "email", None) or getattr(info, "sub", "")
        return self.get_user_by_username(email)

    # ── Password reset hooks (3-step flow) ─────────────────────

    def create_reset_token(self, user: Any) -> str:
        raise NotImplementedError("Override create_reset_token() to use password reset")

    def send_reset_email(self, email: str, token: str, link: str) -> None:
        raise NotImplementedError("Override send_reset_email() to use password reset")

    def validate_reset_token(self, token: str) -> Any | None:
        raise NotImplementedError("Override validate_reset_token() to use password reset")

    def invalidate_password(self, user: Any) -> None:
        raise NotImplementedError("Override invalidate_password() to use password reset")

    def set_password(self, user: Any, new_password: str) -> None:
        raise NotImplementedError("Override set_password() to use password reset")

    # ── Account linking hooks ──────────────────────────────────

    def link_oauth(self, user: Any, info: Any) -> None:
        raise NotImplementedError("Override link_oauth() to use account linking")

    def unlink_oauth(self, user: Any, provider: str) -> None:
        raise NotImplementedError("Override unlink_oauth() to use account linking")

    def link_phone(self, user: Any, phone: str) -> None:
        raise NotImplementedError("Override link_phone() to use account linking")

    def link_email(self, user: Any, email: str) -> None:
        raise NotImplementedError("Override link_email() to use account linking")

    def get_linked_accounts(self, user: Any) -> list[dict[str, Any]]:
        raise NotImplementedError("Override get_linked_accounts() to use account linking")

    # ── Passkey / WebAuthn hooks ───────────────────────────────

    def create_passkey_challenge(self, user: Any | None = None) -> dict[str, Any]:
        raise NotImplementedError("Override create_passkey_challenge() to use passkeys")

    def verify_passkey_registration(self, user: Any, credential: dict[str, Any]) -> None:
        raise NotImplementedError("Override verify_passkey_registration() to use passkeys")

    def verify_passkey_assertion(self, challenge: dict[str, Any], credential: dict[str, Any]) -> Any | None:
        raise NotImplementedError("Override verify_passkey_assertion() to use passkeys")

    def get_user_passkeys(self, user: Any) -> list[dict[str, Any]]:
        raise NotImplementedError("Override get_user_passkeys() to use passkeys")

    def delete_passkey(self, user: Any, credential_id: str) -> None:
        raise NotImplementedError("Override delete_passkey() to use passkeys")

    # ── MFA hooks ──────────────────────────────────────────────

    def is_mfa_enrolled(self, user: Any) -> bool:
        return False

    def get_mfa_methods(self, user: Any) -> list[str]:
        return []

    def enroll_mfa(self, user: Any, method: str) -> dict[str, Any]:
        raise NotImplementedError("Override enroll_mfa() to use MFA")

    def verify_mfa(self, user: Any, method: str, code: str) -> bool:
        raise NotImplementedError("Override verify_mfa() to use MFA")

    # ── Tenant hierarchy hooks ────────────────────────────────

    def resolve_tenant_path(self, user: Any, payload: TokenPayload | None) -> TenantPath | None:
        """Resolve the tenant hierarchy path for the current context.

        Default reads ``tenant_path`` from the token claim, falling back
        to wrapping ``tenant_id`` in a single-node path. Override to
        resolve hierarchy from your database.
        """
        if payload and payload.tenant_path:
            return TenantPath.from_claim(payload.tenant_path)
        if payload and payload.tenant_id:
            return TenantPath.from_flat(payload.tenant_id)
        tenant_id = getattr(user, "tenant_id", None) if user else None
        if tenant_id:
            return TenantPath.from_flat(str(tenant_id))
        return None

    def get_tenant_permissions(self, user: Any, level: str, tenant_id: str) -> list[Permission]:
        """Return permissions scoped to a specific tenant level.

        Override to load tenant-scoped permissions from your database.
        Called for each level in the tenant path (root → leaf) to support
        cascading permission inheritance.
        """
        return []

    # ── Constructor ────────────────────────────────────────────

    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        token_store: TokenStore | None = None,
        session_store: SessionStore | None = None,
        pipeline: Any | None = None,
        event_handler: Any | None = None,
        # Optional callables — pass these to avoid subclassing
        get_user: Callable[..., Any] | None = None,
        get_user_by_username: Callable[..., Any] | None = None,
        verify_password: Callable[..., Any] | None = None,
        get_user_roles: Callable[..., Any] | None = None,
        get_user_permissions: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config or AuthConfig()
        self.pipeline = pipeline
        self.token_store: TokenStore = token_store or MemoryTokenStore()
        self.session_store = session_store
        self.lifecycle = TokenLifecycle(self.config, self.token_store, event_handler=event_handler)
        self.token_service = self.lifecycle.jwt  # backward compat
        # Store callable overrides
        self._get_user_fn = get_user
        self._get_user_by_username_fn = get_user_by_username
        self._verify_password_fn = verify_password
        self._get_user_roles_fn = get_user_roles
        self._get_user_permissions_fn = get_user_permissions

    # ── Async context building ─────────────────────────────────

    async def build_context(
        self,
        raw_token: str | None,
        *,
        optional: bool = False,
        request: Any = None,
    ) -> AuthContext:
        """Build AuthContext from a raw JWT token string."""
        if raw_token is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError()

        try:
            payload: TokenPayload = await self.lifecycle.validate(raw_token)
        except Exception:
            if optional:
                return AuthContext.anonymous(request=request)
            raise

        # Load user
        user = await maybe_await(self.get_user(payload.sub))
        if user is None:
            if optional:
                return AuthContext.anonymous(request=request)
            raise UnauthorizedError("User not found")

        if not getattr(user, "is_active", True):
            raise UnauthorizedError("Inactive user")

        return await self.build_user_context(user, payload=payload, request=request)

    async def build_context_for_user(
        self,
        user: Any,
        *,
        request: Any = None,
    ) -> AuthContext:
        """Build AuthContext from a user object."""
        return await self.build_user_context(user, request=request)

    async def build_user_context(
        self,
        user: Any,
        *,
        payload: TokenPayload | None = None,
        request: Any = None,
    ) -> AuthContext:
        """Load roles/permissions/relations and assemble context."""
        roles = await maybe_await(self.get_user_roles(user))
        direct_permissions = await maybe_await(self.get_user_permissions(user))
        relations = await maybe_await(self.get_user_relations(user))

        all_permissions: list[Permission] = list(direct_permissions)
        for role in roles:
            all_permissions.extend(role.permissions)

        # Resolve tenant hierarchy
        tenant_path = await maybe_await(self.resolve_tenant_path(user, payload))

        # Build scoped permissions from tenant hierarchy (cascading inheritance)
        scopes: dict[str, list[Permission]] = {}
        if tenant_path is not None:
            for node in tenant_path:
                level_perms = await maybe_await(
                    self.get_tenant_permissions(user, node.level, node.id)
                )
                if level_perms:
                    scopes[node.level] = level_perms

        return AuthContext(
            user=user,
            roles=roles,
            permissions=all_permissions,
            relations=relations,
            scopes=scopes,
            token=payload,
            request=request,
            tenant=tenant_path,
        )

    # ── Sync wrappers ──────────────────────────────────────────

    def build_context_sync(
        self,
        raw_token: str | None,
        *,
        optional: bool = False,
        request: Any = None,
    ) -> AuthContext:
        """Sync wrapper for ``build_context``."""
        return run_sync(self.build_context(raw_token, optional=optional, request=request))

    def build_context_for_user_sync(self, user: Any, *, request: Any = None) -> AuthContext:
        """Sync wrapper for ``build_context_for_user``."""
        return run_sync(self.build_context_for_user(user, request=request))

    def check_relation_sync(self, user: Any, relation: Relation, resource_id: str) -> bool:
        """Sync wrapper for ``check_relation``."""
        return run_sync(maybe_await(self.check_relation(user, relation, resource_id)))
