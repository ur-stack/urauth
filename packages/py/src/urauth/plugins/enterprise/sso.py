"""SSO (Single Sign-On) plugin scaffold.

Supports enterprise SSO via SAML 2.0 or OIDC federation. This is a scaffold —
see the notes below on recommended libraries for each protocol.

SAML 2.0: ``pip install python3-saml`` or ``pip install pysaml2``
OIDC federation: use the OAuthPlugin with your IdP's discovery URL.

Usage (once implemented)::

    from urauth.plugins.enterprise import SSOPlugin

    auth = Auth(
        plugins=[
            SSOPlugin(
                protocol="saml",
                entity_id="https://myapp.com",
                idp_metadata_url="https://idp.company.com/metadata",
            )
        ],
        ...
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from urauth.auth import Auth


class SSOPlugin:
    """Enterprise Single Sign-On scaffold (SAML 2.0 / OIDC federation).

    .. note::
        This plugin is not yet fully implemented. It defines the interface
        contract. For production use, integrate ``python3-saml`` (SAML) or
        standard OIDC federation with your IdP.
    """

    id = "sso"

    def __init__(
        self,
        *,
        protocol: Literal["saml", "oidc"] = "saml",
        entity_id: str,
        idp_metadata_url: str | None = None,
        idp_metadata_xml: str | None = None,
        attribute_mapping: dict[str, str] | None = None,
        backend: Any = None,
    ) -> None:
        """
        Args:
            protocol: ``"saml"`` (SAML 2.0) or ``"oidc"`` (OIDC federation).
            entity_id: Service provider entity ID / client ID.
            idp_metadata_url: URL to fetch IdP metadata (SAML) or discovery doc (OIDC).
            idp_metadata_xml: Raw SAML IdP metadata XML (alternative to URL).
            attribute_mapping: Map IdP attributes to urauth user fields.
                e.g. ``{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email"}``
            backend: Custom SAML/OIDC backend. Auto-detected if not provided.
        """
        self.protocol = protocol
        self.entity_id = entity_id
        self.idp_metadata_url = idp_metadata_url
        self.idp_metadata_xml = idp_metadata_xml
        self.attribute_mapping = attribute_mapping or {}
        self._backend = backend

    def setup(self, auth: Auth) -> None:
        auth.sso = self

    async def initiate(self, relay_state: str = "") -> str:
        """Return the SSO redirect URL to send the user to the IdP."""
        raise NotImplementedError("Implement SSO initiation for protocol: " + self.protocol)

    async def process_response(self, response_data: Any) -> dict[str, Any]:
        """Process the IdP response and return normalised user attributes.

        Returns a dict with at least ``{"user_id": ..., "email": ...}``.
        """
        raise NotImplementedError("Implement SSO response processing for protocol: " + self.protocol)

    def map_attributes(self, raw_attributes: dict[str, Any]) -> dict[str, Any]:
        """Apply attribute_mapping to normalise IdP attributes."""
        result: dict[str, Any] = {}
        for idp_key, user_key in self.attribute_mapping.items():
            if idp_key in raw_attributes:
                result[user_key] = raw_attributes[idp_key]
        # Pass through unmapped attributes
        for k, v in raw_attributes.items():
            if k not in self.attribute_mapping and k not in result:
                result[k] = v
        return result
