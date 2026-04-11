"""urauth plugin library.

Pre-built plugins organised by category, mirroring better-auth's plugin
taxonomy. Register any combination via ``Auth(plugins=[...])``.

Categories
----------

**authn** — Authentication: how users prove their identity
    - :class:`~urauth.plugins.authn.UsernamePlugin` — username + password with policy
    - :class:`~urauth.plugins.authn.AnonymousPlugin` — guest sessions before signup
    - :class:`~urauth.plugins.authn.TwoFactorPlugin` — TOTP + backup codes + step-up
    - :class:`~urauth.plugins.authn.MagicLinkPlugin` — signed email magic links
    - :class:`~urauth.plugins.authn.EmailOTPPlugin` — email one-time password
    - :class:`~urauth.plugins.authn.PhoneNumberPlugin` — SMS one-time password
    - :class:`~urauth.plugins.authn.OAuthPlugin` — generic OAuth2 / OIDC login
    - :class:`~urauth.plugins.authn.PasskeyPlugin` — WebAuthn passkeys (scaffold)

**authz** — Authorization: what users are allowed to do
    - :class:`~urauth.plugins.authz.ApiKeyPlugin` — API key management
    - :class:`~urauth.plugins.authz.AdminPlugin` — admin role enforcement
    - :class:`~urauth.plugins.authz.OrganizationPlugin` — multi-tenant orgs

**enterprise** — Enterprise identity integration (scaffolds)
    - :class:`~urauth.plugins.enterprise.OIDCProviderPlugin` — expose as OIDC IdP
    - :class:`~urauth.plugins.enterprise.SSOPlugin` — SAML / OIDC federation
    - :class:`~urauth.plugins.enterprise.SCIMPlugin` — user provisioning

**utility** — Cross-cutting concerns
    - :class:`~urauth.plugins.utility.HibpPlugin` — Have I Been Pwned checks
    - :class:`~urauth.plugins.utility.CaptchaPlugin` — hCaptcha / reCAPTCHA
    - :class:`~urauth.plugins.utility.MultiSessionPlugin` — multiple sessions per user
    - :class:`~urauth.plugins.utility.LastLoginPlugin` — last-login method tracking
    - :class:`~urauth.plugins.utility.JWTPlugin` — JWT parameter configuration
    - :class:`~urauth.plugins.utility.DeviceAuthorizationPlugin` — OAuth device flow
    - :class:`~urauth.plugins.utility.OneTimeTokenPlugin` — single-use tokens

Example::

    from urauth import Auth, JWT
    from urauth.storage.memory import MemoryTokenStore
    from urauth.plugins.authn import UsernamePlugin, TwoFactorPlugin, MagicLinkPlugin
    from urauth.plugins.authz import ApiKeyPlugin, AdminPlugin
    from urauth.plugins.utility import HibpPlugin, LastLoginPlugin

    auth = Auth(
        method=JWT(store=MemoryTokenStore()),
        secret_key="...",
        plugins=[
            UsernamePlugin(policy=PasswordPolicy(min_length=12, require_digit=True)),
            TwoFactorPlugin(backup_code_store=my_backup_store),
            MagicLinkPlugin(send=send_email, base_url="https://myapp.com/auth/magic"),
            ApiKeyPlugin(store=my_api_key_store),
            AdminPlugin(admin_roles={"admin", "staff"}),
            HibpPlugin(),
            LastLoginPlugin(store=my_last_login_store),
        ],
    )
"""

from urauth.plugins import authn, authz, enterprise, utility
from urauth.plugins.authn import (
    AnonymousPlugin,
    EmailOTPPlugin,
    MagicLinkPlugin,
    OAuthPlugin,
    PasskeyPlugin,
    PasswordPolicy,
    PhoneNumberPlugin,
    TwoFactorPlugin,
    UsernamePlugin,
)
from urauth.plugins.authz import AdminPlugin, ApiKeyPlugin, OrgMembership, OrganizationPlugin
from urauth.plugins.enterprise import OIDCProviderPlugin, SCIMPlugin, SSOPlugin
from urauth.plugins.utility import (
    CaptchaPlugin,
    DeviceAuthorizationPlugin,
    DeviceSession,
    DeviceStartResult,
    DeviceStore,
    HibpPlugin,
    JWTPlugin,
    LastLoginPlugin,
    LastLoginStore,
    LoginRecord,
    MultiSessionPlugin,
    OneTimeTokenPlugin,
    SessionRecord,
    SessionTracker,
)

__all__ = [
    # Subpackages
    "authn",
    "authz",
    "enterprise",
    "utility",
    # authn
    "AnonymousPlugin",
    "EmailOTPPlugin",
    "MagicLinkPlugin",
    "OAuthPlugin",
    "PasskeyPlugin",
    "PasswordPolicy",
    "PhoneNumberPlugin",
    "TwoFactorPlugin",
    "UsernamePlugin",
    # authz
    "AdminPlugin",
    "ApiKeyPlugin",
    "OrgMembership",
    "OrganizationPlugin",
    # enterprise
    "OIDCProviderPlugin",
    "SCIMPlugin",
    "SSOPlugin",
    # utility
    "CaptchaPlugin",
    "DeviceAuthorizationPlugin",
    "DeviceSession",
    "DeviceStartResult",
    "DeviceStore",
    "HibpPlugin",
    "JWTPlugin",
    "LastLoginPlugin",
    "LastLoginStore",
    "LoginRecord",
    "MultiSessionPlugin",
    "OneTimeTokenPlugin",
    "SessionRecord",
    "SessionTracker",
]
