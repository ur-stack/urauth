"""urauth FastAPI adapter — requires ``pip install urauth[fastapi]``."""

from __future__ import annotations

try:
    import fastapi  # noqa: F401
except ImportError:
    raise ImportError(
        "FastAPI is required for the urauth.fastapi adapter. "
        "Install with: pip install urauth[fastapi]"
    ) from None

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from fastapi import APIRouter, Depends, FastAPI

from urauth._version import __version__
from urauth.authz.policy.base import Policy
from urauth.backends.base import (
    SessionStore,
    TokenStore,
    UserBackend,
    resolve_user_functions,
)
from urauth.backends.base import (
    UserFunctions as UserFunctions,
)
from urauth.backends.memory import MemoryTokenStore
from urauth.config import AuthConfig
from urauth.fastapi.authz.access import AccessControl
from urauth.fastapi.authz.types import SubjectResolver
from urauth.fastapi.dependencies import CurrentUserDependency
from urauth.fastapi.router import create_password_auth_router
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.fastapi.transport.cookie import CookieTransport
from urauth.fastapi.transport.hybrid import HybridTransport
from urauth.tokens.jwt import TokenService

__all__ = [
    "AuthConfig",
    "CookieTransport",
    "FastAPIAuth",
    "HybridTransport",
    "__version__",
]


class FastAPIAuth:
    """Single entry point for all auth functionality.

    Usage::

        auth = FastAPIAuth(my_backend, AuthConfig(secret_key="..."))
        app = FastAPI(lifespan=auth.lifespan())
        app.include_router(auth.password_auth_router())

        @app.get("/me")
        async def me(user=Depends(auth.current_user())):
            return user
    """

    # ── Overridable user methods (Approach A) ─────────────────

    async def get_user(self, user_id: Any) -> Any | None:
        """Override to fetch a user by ID (Approach A: subclass)."""
        raise NotImplementedError

    async def get_user_by_username(self, username: str) -> Any | None:
        """Override to fetch a user by username/email (Approach A: subclass)."""
        raise NotImplementedError

    async def verify_password(self, user: Any, password: str) -> bool:
        """Override to verify a password (Approach A: subclass)."""
        raise NotImplementedError

    async def create_oauth_user(self, info: Any) -> Any:
        """Override to create a user from OAuth info (Approach A: subclass)."""
        raise NotImplementedError

    def __init__(
        self,
        user_backend: UserBackend | None = None,
        config: AuthConfig | None = None,
        *,
        get_user: Callable[..., Any] | None = None,
        get_user_by_username: Callable[..., Any] | None = None,
        verify_password: Callable[..., Any] | None = None,
        create_oauth_user: Callable[..., Any] | None = None,
        token_store: TokenStore | None = None,
        session_store: SessionStore | None = None,
        transport: Any | None = None,
    ) -> None:
        self.config = config or AuthConfig()
        self.backend = user_backend
        self.token_store: TokenStore = token_store or MemoryTokenStore()
        self.session_store = session_store
        self.token_service = TokenService(self.config)

        # Default transport: bearer
        if transport is not None:
            self._transport = transport
        else:
            self._transport = BearerTransport()

        # Resolve user functions from one of three sources
        self._user_fns = resolve_user_functions(
            auth_instance=self,
            base_class=FastAPIAuth,
            user_backend=user_backend,
            get_user=get_user,
            get_user_by_username=get_user_by_username,
            verify_password=verify_password,
            create_oauth_user=create_oauth_user,
        )

        # RBAC / permissions (wired in Phase 3)
        self._rbac_manager: Any | None = None
        self._permission_manager: Any | None = None

        # OAuth providers (wired in Phase 2)
        self._oauth_manager: Any | None = None
        self._oauth_providers: dict[str, dict[str, Any]] = {}

        # Build the user dependency factory
        self._user_dep = CurrentUserDependency(
            token_service=self.token_service,
            transport=self._transport,
            user_fns=self._user_fns,
            token_store=self.token_store,
            rbac_manager=self._rbac_manager,
            permission_manager=self._permission_manager,
        )

    # ── Dependencies ────────────────────────────────────────────

    def current_user(self, **kwargs: Any) -> Any:
        """Return a FastAPI ``Depends()`` callable resolving the current user.

        Keyword args are forwarded to ``CurrentUserDependency.__call__``:
        ``active``, ``verified``, ``scopes``, ``roles``, ``permissions``,
        ``fresh``, ``optional``.
        """
        return Depends(self._user_dep(**kwargs))

    def requires(
        self,
        *,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> Any:
        """Shorthand dependency that only checks authorization (returns user)."""
        return self.current_user(roles=roles, permissions=permissions, scopes=scopes)

    # ── Routers ─────────────────────────────────────────────────

    def password_auth_router(self, **kwargs: Any) -> APIRouter:
        """Return an APIRouter with login/refresh/logout endpoints."""
        return create_password_auth_router(
            user_fns=self._user_fns,
            token_service=self.token_service,
            token_store=self.token_store,
            transport=self._transport,
            config=self.config,
        )

    # ── OAuth (Phase 2) ────────────────────────────────────────

    def register_oauth_provider(
        self,
        name: str,
        *,
        client_id: str,
        client_secret: str,
        **kwargs: Any,
    ) -> None:
        """Register an OAuth2/OIDC provider for social login."""
        self._oauth_providers[name] = {
            "client_id": client_id,
            "client_secret": client_secret,
            **kwargs,
        }
        if self._oauth_manager is None:
            from urauth.authn.oauth2.client import OAuthManager

            self._oauth_manager = OAuthManager()

        self._oauth_manager.register(name, client_id=client_id, client_secret=client_secret, **kwargs)

    def oauth_router(self, provider: str, **kwargs: Any) -> APIRouter:
        """Return an APIRouter with OAuth login/callback endpoints for a provider."""
        if self._oauth_manager is None:
            raise RuntimeError(f"Provider '{provider}' not registered. Call register_oauth_provider() first.")

        from urauth.fastapi.authn.oauth2.routes import create_oauth_router

        return create_oauth_router(
            provider=provider,
            oauth_manager=self._oauth_manager,
            token_service=self.token_service,
            token_store=self.token_store,
            user_fns=self._user_fns,
            transport=self._transport,
            config=self.config,
            **kwargs,
        )

    # ── RBAC (Phase 3) ─────────────────────────────────────────

    def set_rbac(self, role_hierarchy: dict[str, list[str]]) -> None:
        """Configure role-based access control with a role hierarchy."""
        from urauth.authz.rbac import RBACManager

        self._rbac_manager = RBACManager(role_hierarchy)
        self._rebuild_user_dep()

    def set_permissions(self, role_permissions: dict[str, set[str]]) -> None:
        """Configure permission-based authorization."""
        from urauth.authz.permissions import PermissionManager

        self._permission_manager = PermissionManager(role_permissions)
        self._rebuild_user_dep()

    def _rebuild_user_dep(self) -> None:
        self._user_dep = CurrentUserDependency(
            token_service=self.token_service,
            transport=self._transport,
            user_fns=self._user_fns,
            token_store=self.token_store,
            rbac_manager=self._rbac_manager,
            permission_manager=self._permission_manager,
        )

    # ── Access Control (Policy-based) ─────────────────────────

    def access_control(
        self,
        policy: Policy,
        subject_resolver: SubjectResolver | None = None,
        **kwargs: Any,
    ) -> AccessControl[Any, Any, Any]:
        """Return an AccessControl instance wired to this auth system's JWT decoder."""
        if subject_resolver is None:
            from urauth.fastapi.authz.contrib.jwt import jwt_subject_resolver

            subject_resolver = jwt_subject_resolver(decode=self.token_service.decode_token)

        return AccessControl(policy=policy, subject_resolver=subject_resolver, **kwargs)

    # ── App setup ────────────────────────────────────────────────

    def init_app(self, app: FastAPI) -> None:
        """Register exception handlers on a FastAPI app.

        Call this after creating the app but before the first request::

            app = FastAPI(lifespan=auth.lifespan())
            auth.init_app(app)
        """
        from urauth.fastapi.exceptions import register_exception_handlers

        register_exception_handlers(app)

    def lifespan(self) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        """Return an ASGI lifespan context manager for FastAPI."""

        @asynccontextmanager
        async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
            yield

        return _lifespan
