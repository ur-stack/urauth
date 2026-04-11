"""Authorization plugins for urauth.

Each plugin handles one aspect of what users are allowed to do.
"""

from urauth.plugins.authz.admin import AdminPlugin
from urauth.plugins.authz.api_key import ApiKeyPlugin
from urauth.plugins.authz.organization import OrgMembership, OrganizationPlugin

__all__ = [
    "AdminPlugin",
    "ApiKeyPlugin",
    "OrgMembership",
    "OrganizationPlugin",
]
