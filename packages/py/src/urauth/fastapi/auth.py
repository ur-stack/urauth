"""FastAPI adapter — single entry point via ``FastAuth``."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, TypeVar

from fastapi import APIRouter, Depends, FastAPI
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request

from urauth.auth import Auth
from urauth.authz.primitives import AnyOf, Relation, Requirement
from urauth.context import AuthContext
from urauth.exceptions import UnauthorizedError
from urauth.fastapi._guards import PolicyGuard, RelationGuard, RequirementGuard
from urauth.fastapi.authz.access import AccessControl
from urauth.fastapi.authz.tenant_guard import TenantGuard
from urauth.fastapi.exceptions import register_exception_handlers
from urauth.fastapi.resolvers import build_resolver
from urauth.fastapi.routes import RouterBuilder
from urauth.fastapi.transport.bearer import BearerTransport
from urauth.fastapi.transport.cookie import CookieTransport
from urauth.fastapi.transport.hybrid import HybridTransport
from urauth.methods import JWT, Fallback

F = TypeVar("F", bound=Callable[..., Any])

# Shared security scheme — auto_error=False so urauth handles errors itself.
_BEARER_SCHEME = Depends(HTTPBearer(auto_error=False))


class FastAuth:
    """FastAPI adapter wrapping the framework-agnostic ``Auth``.

    Provides FastAPI-specific features: ``Depends()`` support, dual-use guards,
    token extraction from Request via Transport, and checker-based access control.

    All guards work as both decorators and FastAPI dependencies::

        # Decorator style
        @app.get("/users")
        @auth.require(can_read_users)
        async def list_users(ctx: AuthContext = Depends(auth.context)):
            return ctx.user

        # Dependency style
        @app.get("/users", dependencies=[Depends(auth.require(can_read_users))])
        async def list_users():
            ...
    """

    def __init__(
        self,
        auth: Auth,
        *,
        transport: Any | None = None,
    ) -> None:
        self._auth = auth
        self._transport = self._build_transport(transport)
        self._resolver = build_resolver(auth.method, auth, self._transport)

    def _build_transport(self, override: Any | None) -> Any:
        """Build the right transport from auth method config."""
        if override is not None:
            return override

        method = self._auth.method

        # Check the primary method or first JWT in a Fallback
        jwt_method: JWT | None = None
        if isinstance(method, JWT):
            jwt_method = method
        elif isinstance(method, Fallback):
            for m in method.methods:
                if isinstance(m, JWT):
                    jwt_method = m
                    break

        if jwt_method is not None:
            if jwt_method.transport == "cookie":
                return CookieTransport(self._auth.internal_config)
            if jwt_method.transport == "hybrid":
                return HybridTransport(BearerTransport(), CookieTransport(self._auth.internal_config))

        return BearerTransport()

    # ── Expose core Auth properties ─────────────────────────────────

    @property
    def config(self) -> Any:
        """Internal config for backward compat (middleware, transports)."""
        return self._auth.internal_config

    @property
    def lifecycle(self) -> Any:
        return self._auth.lifecycle

    @property
    def token_service(self) -> Any:
        return self._auth.token_service

    @property
    def token_store(self) -> Any:
        return self._auth.token_store

    @property
    def session_store(self) -> Any:
        return self._auth.session_store

    # ── Single context resolution (all guards use this) ─────────

    async def context(
        self,
        request: Request,
        _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
    ) -> AuthContext:
        """FastAPI dependency returning AuthContext.

        Cached on ``request.state._auth_context`` — only built once per request.
        The ``HTTPBearer`` dependency makes Swagger show the lock icon and
        "Authorize" button automatically.

        Usage::

            ctx: AuthContext = Depends(auth.context)
        """
        cached = getattr(request.state, "_auth_context", None)
        if cached is not None:
            return cached

        # Determine if optional from endpoint marker
        optional = getattr(request.state, "_urauth_optional", False)
        if not optional:
            route = request.scope.get("route")
            if route:
                endpoint = getattr(route, "endpoint", None)
                if endpoint:
                    optional = getattr(endpoint, "_urauth_optional", False)

        ctx = await self._resolver.resolve(request, optional=optional)
        request.state._auth_context = ctx
        return ctx

    # ── Current user dependency ─────────────────────────────────────

    @property
    def current_user(self) -> Callable[..., Any]:
        """FastAPI dependency returning the authenticated user object.

        Usage::

            user = Depends(auth.current_user)
        """
        auth = self

        async def _dependency(
            request: Request,
            _credentials: HTTPAuthorizationCredentials | None = _BEARER_SCHEME,
        ) -> Any:
            ctx = await auth.context(request, _credentials)
            if not ctx.is_authenticated():
                raise UnauthorizedError()
            return ctx.user

        return _dependency

    # ── Optional auth marker ────────────────────────────────────────

    @property
    def optional(self) -> Callable[[F], F]:
        """Decorator marking an endpoint as optional authentication.

        Usage::

            @app.get("/feed")
            @auth.optional
            async def feed(ctx: AuthContext = Depends(auth.context)):
                if ctx.is_authenticated():
                    return {"feed": "personalized"}
                return {"feed": "public"}
        """

        def decorator(func: F) -> F:
            func._urauth_optional = True  # type: ignore[attr-defined]
            return func

        return decorator  # type: ignore[return-value]

    # ── Guards (dual-use: decorator + Depends) ──────────────────

    def require(self, requirement: Requirement) -> RequirementGuard:
        """Guard requiring a specific permission, role, or composite requirement."""
        return RequirementGuard(self.context, requirement)

    req = require  # alias

    def require_any(self, *requirements: Requirement) -> RequirementGuard:
        """Guard requiring ANY of the given requirements."""
        return RequirementGuard(self.context, AnyOf(list(requirements)))

    req_any = require_any  # alias

    def require_relation(
        self,
        relation: Relation,
        *,
        resource_id_from: str,
    ) -> RelationGuard:
        """Guard requiring a Zanzibar relation to a resource."""
        return RelationGuard(self.context, self._auth, relation, resource_id_from)

    req_relation = require_relation  # alias

    def policy(
        self,
        check: Callable[[AuthContext], bool] | Callable[[AuthContext], Any],
    ) -> PolicyGuard:
        """Guard with arbitrary policy logic."""
        return PolicyGuard(self.context, check)

    # ── Tenant guard ─────────────────────────────────────────────────

    def require_tenant(
        self,
        *,
        level: str | None = None,
        requirement: Requirement | None = None,
    ) -> TenantGuard:
        """Guard requiring a tenant context."""
        return TenantGuard(self.context, level=level, requirement=requirement)

    req_tenant = require_tenant  # alias

    # ── Checker-based access control ────────────────────────────

    def access_control(
        self,
        checker: Any | None = None,
        *,
        registry: Any | None = None,
        on_deny: Callable[..., Any] | None = None,
        auto_error: bool = True,
    ) -> Any:
        """Create an AccessControl instance wired to this auth's context resolution."""
        if registry is not None and checker is None:
            checker = registry.build_checker()

        return AccessControl(
            context_resolver=self.context,
            checker=checker,
            on_deny=on_deny,
            auto_error=auto_error,
        )

    # ── Routers ─────────────────────────────────────────────────

    def auto_router(self) -> APIRouter:
        """Generate all auth routes from the Auth configuration.

        Reads enabled login methods, features, and lifecycle config
        from the ``Auth`` instance and creates endpoints accordingly.
        """
        builder = RouterBuilder(self._auth, self._transport)
        return builder.build()

    def password_auth_router(self, **kwargs: Any) -> APIRouter:
        """Backward compat: return a router with login/refresh/logout.

        Ensures password login is enabled even if not explicitly configured,
        then delegates to ``auto_router()``.
        """
        from urauth.methods import Password as _Password
        if self._auth.password is None:
            self._auth.password = _Password()
        return self.auto_router()

    # ── App setup ───────────────────────────────────────────────

    def init_app(self, app: FastAPI) -> None:
        """Register exception handlers on a FastAPI app."""
        register_exception_handlers(app)

    def lifespan(self) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        """Return an ASGI lifespan context manager."""

        @asynccontextmanager
        async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
            yield

        return _lifespan
