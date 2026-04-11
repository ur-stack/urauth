"""SCIM 2.0 (System for Cross-domain Identity Management) plugin scaffold.

SCIM allows enterprise IdPs (Okta, Azure AD, Google Workspace) to
automatically provision and de-provision users in your application.

RFC 7643 defines the schema. RFC 7644 defines the protocol (HTTP endpoints).

Usage (once implemented)::

    from urauth.plugins.enterprise import SCIMPlugin

    auth = Auth(
        plugins=[
            SCIMPlugin(
                bearer_token="scim-secret-token",
                user_store=my_user_store,
            )
        ],
        ...
    )

    # Mount SCIM routes (framework-specific, e.g. FastAPI)
    app.include_router(auth.scim.router(), prefix="/scim/v2")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from urauth.auth import Auth


class SCIMPlugin:
    """SCIM 2.0 user provisioning scaffold.

    Provides the interface for enterprise identity provider integration.
    The ``user_store`` is responsible for creating, updating, and deactivating
    users in response to SCIM commands.

    .. note::
        This plugin defines the interface contract. Mount ``auth.scim.router()``
        in your framework to expose the SCIM endpoints.
    """

    id = "scim"

    def __init__(
        self,
        *,
        bearer_token: str,
        user_store: Any = None,
        base_path: str = "/scim/v2",
        supported_schemas: list[str] | None = None,
    ) -> None:
        """
        Args:
            bearer_token: Static bearer token for SCIM endpoint authentication.
                          For production, use per-client tokens with rotation.
            user_store: Object implementing SCIM user operations:
                ``create(attrs)``, ``get(scim_id)``, ``update(scim_id, attrs)``,
                ``delete(scim_id)``, ``list(filter, start_index, count)``.
            base_path: Base path for SCIM endpoints.
            supported_schemas: SCIM schemas to advertise in the ServiceProviderConfig.
        """
        self._token = bearer_token
        self._store = user_store
        self.base_path = base_path
        self.supported_schemas = supported_schemas or [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:core:2.0:Group",
        ]

    def setup(self, auth: Auth) -> None:
        auth.scim = self

    def service_provider_config(self) -> dict[str, Any]:
        """Return the SCIM ServiceProviderConfig response."""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": True}
            ],
        }

    async def get_user(self, scim_id: str) -> dict[str, Any]:
        """Fetch a user by SCIM ID."""
        raise NotImplementedError("Implement SCIM user fetch via user_store")

    async def create_user(self, attributes: dict[str, Any]) -> dict[str, Any]:
        """Provision a new user from SCIM attributes."""
        raise NotImplementedError("Implement SCIM user creation via user_store")

    async def update_user(self, scim_id: str, attributes: dict[str, Any]) -> dict[str, Any]:
        """Update an existing user (PUT replaces, PATCH patches)."""
        raise NotImplementedError("Implement SCIM user update via user_store")

    async def delete_user(self, scim_id: str) -> None:
        """Deprovision (deactivate) a user."""
        raise NotImplementedError("Implement SCIM user deletion via user_store")

    async def list_users(
        self,
        *,
        filter_expr: str | None = None,
        start_index: int = 1,
        count: int = 100,
    ) -> dict[str, Any]:
        """List users with optional SCIM filter expression."""
        raise NotImplementedError("Implement SCIM user listing via user_store")
