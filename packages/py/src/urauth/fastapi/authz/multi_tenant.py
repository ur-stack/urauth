"""Multi-tenant resolution from JWT claims, headers, path params, or subdomains."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Request

from urauth.config import AuthConfig
from urauth.exceptions import ForbiddenError
from urauth.types import TokenPayload


class TenantResolver:
    """Resolve the current tenant from various request sources."""

    def __init__(self, config: AuthConfig) -> None:
        self._config = config

    def current_tenant(self) -> Callable:
        """Return a FastAPI dependency that resolves the current tenant ID."""
        config = self._config

        async def _resolve(request: Request) -> str:
            tenant_id: str | None = None

            # 1. Try JWT claim (set by token validation middleware)
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

            if not tenant_id:
                raise ForbiddenError("Tenant ID could not be resolved")

            return tenant_id

        return _resolve
