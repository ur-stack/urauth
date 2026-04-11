"""Enterprise plugins for urauth.

These plugins handle enterprise identity integration scenarios.
Most require additional setup or third-party libraries.
"""

from urauth.plugins.enterprise.oidc_provider import OIDCProviderPlugin
from urauth.plugins.enterprise.scim import SCIMPlugin
from urauth.plugins.enterprise.sso import SSOPlugin

__all__ = [
    "OIDCProviderPlugin",
    "SCIMPlugin",
    "SSOPlugin",
]
