"""Multi-tenant resolution from JWT claims, headers, path params, or subdomains."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request

from urauth.config import AuthConfig
from urauth.exceptions import ForbiddenError
from urauth.tenant.hierarchy import TenantPath
from urauth.tenant.protocols import TenantStore
from urauth.types import TokenPayload


def _resolve_flat_tenant_id(request: Request, config: AuthConfig) -> str | None:
    """Extract a flat tenant_id from request sources (shared logic)."""
    tenant_id: str | None = None

    # 1. Try JWT claim
    payload: TokenPayload | None = getattr(request.state, "token_payload", None)
    if payload and payload.tenant_id:
        tenant_id = payload.tenant_id

    # 2. Try header
    if not tenant_id:
        tenant_id = request.headers.get(config.tenant_header)

    # 3. Try path param
    if not tenant_id:
        tenant_id = request.path_params.get("tenant_id")

    # 4. Try subdomain
    if not tenant_id:
        host = request.headers.get("host", "")
        parts = host.split(".")
        if len(parts) >= 3:
            tenant_id = parts[0]

    return tenant_id


class TenantResolver:
    """Resolve the current tenant from various request sources.

    Supports both flat tenant ID resolution (backward compat) and
    hierarchical tenant path resolution::

        resolver = TenantResolver(config)
        tenant_id = Depends(resolver.current_tenant())      # flat string
        tenant_path = Depends(resolver.current_tenant_path())  # TenantPath
    """

    def __init__(
        self,
        config: AuthConfig,
        *,
        store: TenantStore | None = None,
    ) -> None:
        self._config = config
        self._store = store

    def current_tenant(self) -> Callable[..., Any]:
        """Return a FastAPI dependency that resolves the current tenant ID."""
        config = self._config

        async def _resolve(request: Request) -> str:
            tenant_id = _resolve_flat_tenant_id(request, config)
            if not tenant_id:
                raise ForbiddenError("Tenant ID could not be resolved")
            return tenant_id

        return _resolve

    def current_tenant_path(self) -> Callable[..., Any]:
        """Return a FastAPI dependency that resolves the full tenant hierarchy path.

        Resolution order:
        1. ``tenant_path`` JWT claim → ``TenantPath.from_claim()``
        2. Flat ``tenant_id`` → ``TenantStore.resolve_path()`` if store available
        3. Flat ``tenant_id`` → ``TenantPath.from_flat()`` fallback
        """
        config = self._config
        store = self._store

        async def _resolve(request: Request) -> TenantPath:
            # 1. Try tenant_path from JWT claim
            payload: TokenPayload | None = getattr(request.state, "token_payload", None)
            if payload and payload.tenant_path:
                return TenantPath.from_claim(payload.tenant_path)

            # 2. Resolve flat tenant_id
            tenant_id = _resolve_flat_tenant_id(request, config)

            # 3. If we have a store, resolve full path from DB
            if tenant_id and store is not None:
                path = await store.resolve_path(tenant_id)
                if path is not None:
                    return path

            # 4. Fall back to single-node path
            if tenant_id:
                return TenantPath.from_flat(tenant_id)

            raise ForbiddenError("Tenant could not be resolved")

        return _resolve
